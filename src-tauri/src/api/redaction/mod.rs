//! Object-level redaction producer endpoints (ADR-0026 / ADR-0030).
//!
//! Routes
//! ------
//! * `POST /redaction/describe` — classify an already-committed PDF's objects
//!   into human labels + previews for the producer UI (ADR-0029 Phase A1).
//!   Presentation only: never persisted, never part of the commitment.
//! * `POST /redaction/redact` — Olympus-owned redaction (ADR-0030 V3): upload the
//!   committed document + segment ids to hide, get back the redacted artifact
//!   **and** the V3 signed-Merkle bundle bound to it.
//! * `GET /redaction/manifest/{content_hash}` — operator-facing listing of a
//!   committed document's redactable segments.
//!
//! The producer loads the **segment manifest persisted at ingest**
//! (`redaction_segment_manifests`, ADR-0026), whose ADR-0030 variable-depth root
//! matches the commitment on the ledger. The per-segment leaf is the hiding
//! Pedersen commitment from `olympus_crypto::redaction`; revealed segments'
//! blindings are published in the bundle so a recipient can recompute their
//! leaves. The Groth16 `redaction_validity` proof is dropped (ADR-0030 §4): the
//! bundle's binding rests on the Ed25519-signed segment table + the fold to the
//! on-ledger root.

mod bundle_v3;
mod describe;
mod manifest;
mod redact;
mod types;

#[cfg(test)]
mod tests;

pub use types::{
    ManifestObject, RedactionDescribeRequest, RedactionDescribeResponse, RedactionManifestResponse,
    RedactionRedactRequest, RedactionRedactResponse,
};

use axum::{
    routing::{get, post},
    Router,
};

use crate::state::AppState;

pub fn router() -> Router<AppState> {
    Router::new()
        .route(
            "/redaction/manifest/{content_hash}",
            get(manifest::get_manifest),
        )
        .route("/redaction/describe", post(describe::describe_redaction))
        .route("/redaction/redact", post(redact::redact_redaction))
}
