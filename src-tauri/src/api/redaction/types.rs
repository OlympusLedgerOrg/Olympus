//! Shared request / response types and small error / scope helpers for the
//! object-level redaction endpoints (ADR-0026).

use axum::{http::StatusCode, Json};
use serde::{Deserialize, Serialize};

use crate::api::middleware::auth::AuthenticatedKey;

// ── Error helper ──────────────────────────────────────────────────────────────

pub(crate) type ApiError = (StatusCode, Json<serde_json::Value>);

pub(crate) fn err(status: StatusCode, detail: &str) -> ApiError {
    (status, Json(serde_json::json!({ "detail": detail })))
}

pub(crate) fn db_err(e: sqlx::Error) -> ApiError {
    tracing::error!("database error: {e}");
    err(StatusCode::INTERNAL_SERVER_ERROR, "Database error.")
}

// ── Request / response types ──────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct RedactionIssueRequest {
    /// BLAKE3 content hash (64-hex) of the original (already-committed) PDF.
    pub content_hash: String,
    /// Indirect-object ids to **hide**. Every other in-use object is revealed.
    pub redacted_obj_ids: Vec<u32>,
    /// Decimal-string Fr identifying the recipient (opaque to the circuit; by
    /// convention the recipient's BJJ public-key X coordinate).
    pub recipient_id: String,
}

/// Published blinding for one revealed object so the recipient can recompute its
/// hiding leaf `Poseidon(content·G + b·H)` (ADR-0026).
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RevealedSegment {
    pub segment_id: u32,
    /// Decimal Baby Jubjub subgroup scalar `b`.
    pub blinding_decimal: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RedactionIssueResponse {
    pub circuit: String,
    pub content_hash: String,
    pub original_root: String,
    pub proof_json: serde_json::Value,
    pub public_signals: Vec<String>,
    /// The object ids that were hidden (mirrors the request, for the bundle).
    pub redacted_obj_ids: Vec<u32>,
    /// Per-revealed-object blindings — the recipient recomputes `content` from
    /// the artifact bytes and `leaf = Poseidon((content·G + b·H).x, .y)` and
    /// checks the redactedCommitment public signal.
    pub revealed_segments: Vec<RevealedSegment>,
    /// 64-byte Ed25519 sig (lowercase hex) over the length-prefixed payload
    /// `"OLY:REDACTION_BUNDLE:V2" || lp(content_hash) || lp(original_root) ||
    /// lp(redacted_commitment) || lp(recipient_id)` (canonical-decimal recipient).
    pub signature_hex: String,
}

#[derive(Deserialize)]
pub struct RedactionRedactRequest {
    /// Base64 of the original (already-committed) PDF's raw bytes.
    pub original_base64: String,
    /// Indirect-object ids to hide.
    pub redacted_obj_ids: Vec<u32>,
    /// Recipient field element (decimal string), as in `/redaction/issue`.
    pub recipient_id: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RedactionRedactResponse {
    /// Base64 of the redacted artifact. Same length as the original for the
    /// in-place formats (traditional PDF / text); for OOXML and modern
    /// (xref-stream) PDFs it is a canonically re-emitted container, so its bytes
    /// and length differ from the upload while every revealed segment's leaf
    /// still recomputes from it.
    pub redacted_base64: String,
    /// The `redaction_validity` bundle bound to the artifact above.
    pub bundle: RedactionIssueResponse,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ManifestObject {
    /// Segment id (== `segment_id` in the bundle's `revealed_segments`). PDF: the
    /// indirect-object id; text: the 0-based line-block index.
    pub segment_id: u32,
    /// Length in bytes of the segment's span in the original artifact.
    pub byte_length: u64,
    /// Producer-facing label — a text block's `"lines 12-18"`; `null` for PDF
    /// (the `segment_id` is itself the object's label there).
    pub label: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RedactionManifestResponse {
    pub content_hash: String,
    /// Commitment format tag (`pdf-object` / `text-line` / `ooxml-part`) so the
    /// producer UI can render the right selection affordance.
    pub format: String,
    pub original_root: String,
    pub object_count: usize,
    pub objects: Vec<ManifestObject>,
}

pub(crate) fn require_redact_scope(auth: &AuthenticatedKey) -> Result<(), ApiError> {
    if !auth.has_scope("redact")
        && !auth.has_scope("write")
        && !auth.has_scope("ingest")
        && !auth.has_scope("admin")
    {
        return Err(err(
            StatusCode::FORBIDDEN,
            "API key lacks required scope: one of 'redact', 'write', 'ingest', or 'admin'.",
        ));
    }
    Ok(())
}
