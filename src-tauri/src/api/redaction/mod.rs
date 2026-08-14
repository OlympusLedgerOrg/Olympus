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
// ADR-0037: object-based redaction selection, staging, and commit flow
// (`get_page_objects` / `stage_redaction` / `commit_redaction`).
/// `pub` (not just crate-visible) so DB-backed integration tests
/// (`tests/api_db/ingest_signing_key_registry.rs`) can call `get_issuer_key`
/// directly with a manually assembled `AppState` — the shared test harness's
/// `AppState` (`tests/common/mod.rs::init`) does not resolve an ingest
/// signing key the way `main.rs`/`bin/olympus-server.rs` do, so exercising
/// `history` end-to-end against a real pool needs to bypass the harness's
/// server and call the handler directly, same pattern as this module's own
/// unit tests already use.
pub mod issuer_key;
mod manifest;
mod redact;
mod selection;
pub(crate) mod staging;
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
        // ADR-0037 selection flow: get_page_objects / stage_redaction / commit_redaction.
        .route("/redaction/page-objects", post(selection::get_page_objects))
        .route("/redaction/stage", post(selection::stage_redaction))
        .route("/redaction/commit", post(selection::commit_redaction))
        // Unauthenticated: the bundle-signing public key is public by design.
        .route("/redaction/issuer-key", get(issuer_key::get_issuer_key))
}
