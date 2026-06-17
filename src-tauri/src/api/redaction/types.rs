//! Shared request / response types and small error / scope helpers for the
//! object-level redaction endpoints (ADR-0026).

use axum::{http::StatusCode, Json};
use serde::{Deserialize, Serialize};

use crate::api::middleware::auth::AuthenticatedKey;
use crate::zk::pdf_describe::ObjectDescription;

// ── Error helper ──────────────────────────────────────────────────────────────

pub(crate) type ApiError = (StatusCode, Json<serde_json::Value>);

pub(crate) fn err(status: StatusCode, detail: &str) -> ApiError {
    (status, Json(serde_json::json!({ "detail": detail })))
}

pub(crate) fn db_err(e: sqlx::Error) -> ApiError {
    tracing::error!("database error: {e}");
    err(StatusCode::INTERNAL_SERVER_ERROR, "Database error.")
}

/// The BN254 scalar field modulus as a `BigUint`, for the V3 bundle's
/// canonical-range checks (`original_root` / `leaf_hex` / `recipient_id` must be
/// `< r`).
pub(crate) fn bn254_fr_modulus() -> num_bigint::BigUint {
    use ark_ff::{BigInteger, PrimeField};
    num_bigint::BigUint::from_bytes_be(&ark_bn254::Fr::MODULUS.to_bytes_be())
}

// ── Request / response types ──────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct RedactionRedactRequest {
    /// Base64 of the original (already-committed) document's raw bytes.
    pub original_base64: String,
    /// Segment ids to hide (PDF indirect-object id / text block / OOXML part).
    pub redacted_obj_ids: Vec<u32>,
    /// Recipient field element (decimal string), by convention the recipient's
    /// BJJ public-key X coordinate.
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
    /// The ADR-0030 V3 signed-Merkle bundle bound to the artifact above.
    pub bundle: crate::api::redaction::bundle_v3::V3Bundle,
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

// ── ADR-0029 Phase A1: POST /redaction/describe ───────────────────────────────

#[derive(Deserialize)]
pub struct RedactionDescribeRequest {
    /// BLAKE3 content hash (64-hex) of the original (already-committed) PDF.
    pub content_hash: String,
    /// Base64 of the original PDF's raw bytes. Re-parsed on demand to classify
    /// objects; **never persisted and never part of the commitment** (the
    /// labels/previews are presentation only — ADR-0029 §A).
    pub original_base64: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RedactionDescribeResponse {
    pub content_hash: String,
    /// Commitment format tag; describe (A1) only supports `pdf-object`.
    pub format: String,
    pub object_count: usize,
    /// Per-committed-object classification + label + preview, obj-id-ascending
    /// (same set/order as the manifest's `objects`).
    pub objects: Vec<ObjectDescription>,
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
