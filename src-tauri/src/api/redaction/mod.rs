//! Object-level redaction producer endpoints (ADR-0026).
//!
//! Routes
//! ------
//! * `POST /redaction/issue`  — prove a redaction of an already-committed PDF,
//!   selecting indirect objects to hide by id.
//! * `POST /redaction/redact` — Olympus-owned redaction: upload the committed
//!   PDF + object ids to hide, get back the zero-filled artifact **and** the
//!   `redaction_validity` bundle bound to it.
//!
//! Both build the 1024-leaf witness from the **object manifest persisted at
//! ingest** (`redaction_segment_manifests`, ADR-0026 Phase 4), so the proof's
//! `originalRoot` matches the object-level root committed on the ledger. The
//! per-object leaf is the hiding Pedersen commitment from
//! `olympus_crypto::redaction`; revealed objects' blindings are published in the
//! bundle so a recipient can recompute their leaves.
//!
//! The legacy chunk-based `/redaction/link` + `/redaction/redact` byte-range
//! path (ADR-0023/0025 chunk scheme) was removed with ADR-0026; `chunk.rs`
//! remains only as the general (non-PDF) ingest commitment.

mod bundle_v3;
mod issue;
mod manifest;
mod redact;
mod types;

#[cfg(test)]
mod tests;

pub use types::{
    ManifestObject, RedactionIssueRequest, RedactionIssueResponse, RedactionManifestResponse,
    RedactionRedactRequest, RedactionRedactResponse, RevealedSegment,
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
        .route("/redaction/issue", post(issue::issue_redaction))
        .route("/redaction/redact", post(redact::redact_redaction))
}
