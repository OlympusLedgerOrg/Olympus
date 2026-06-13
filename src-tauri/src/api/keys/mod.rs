//! Key management routes — port of selected endpoints from `api/routers/keys.py`.
//!
//! In scope for Phase 2B
//! ---------------------
//! POST   /key/admin/generate          — generate API key material (admin-protected)
//! POST   /key/admin/reload-keys       — verify admin auth + report DB key count
//! POST   /key/signing                 — register an Ed25519 signing key
//! GET    /key/signing                 — list caller's signing keys
//! DELETE /key/signing/{key_id}        — revoke a signing key
//! POST   /key/signing/dev-generate    — dev-only first-boot helper
//!
//! Deferred to a later phase
//! -------------------------
//! Credential issue/revoke, consent challenges, EVM mint-queue, wallet binding.
//! Those endpoints require additional DB tables (key_credentials,
//! credential_consents, evm_pending_ops, account_wallet_bindings) not yet
//! present in the Phase 2B schema.
//!
//! # Signing-key possession proof
//!
//! POST /key/signing requires an Ed25519 signature over the canonical JSON:
//! `{"domain":"OLYMPUS:SIGNING_KEY_BINDING:V1","label":"…","public_key":"…","purpose":"…"}`
//! (keys lexicographically sorted, no whitespace — matches `signing_key_binding_payload`
//! in the Python router).
//!
//! Module layout: `admin` holds the `x-admin-key`-gated endpoints, `signing`
//! the user-facing signing-key operations, and `common` the shared
//! types/helpers. This parent module re-exports the public surface so callers
//! keep importing `crate::api::keys::*` unchanged.

mod admin;
mod common;
mod signing;

use axum::{
    routing::{delete, post},
    Router,
};

use crate::state::AppState;

use admin::{admin_generate_key, admin_reload_keys};
#[cfg(feature = "dev-signing-route")]
use signing::dev_generate_signing_key;
use signing::{list_signing_keys, register_signing_key, revoke_signing_key};

pub use common::{
    GenerateKeyRequest, GenerateKeyResponse, SigningKeyRegisterRequest, SigningKeyResponse,
};
#[cfg(feature = "dev-signing-route")]
pub use common::{SigningKeyDevGenerateRequest, SigningKeyDevGenerateResponse};
pub use signing::RevokeSigningKeyParams;

// ── Router ────────────────────────────────────────────────────────────────────

// `clippy::let_and_return`: with the `dev-signing-route` feature off (the
// default) the body collapses to `let router = …; router`, because the
// dev-generate route is appended via a `#[cfg]` shadowing binding — the
// standard idiom for a cfg-gated builder tail.
#[allow(clippy::let_and_return)]
pub fn router() -> Router<AppState> {
    let router = Router::new()
        .route("/key/admin/generate", post(admin_generate_key))
        .route("/key/admin/reload-keys", post(admin_reload_keys))
        .route(
            "/key/signing",
            post(register_signing_key).get(list_signing_keys),
        )
        .route("/key/signing/{key_id}", delete(revoke_signing_key));

    // Dev-only first-boot helper that returns a freshly generated Ed25519
    // PRIVATE key in its response body. Gated behind the opt-in
    // `dev-signing-route` feature (OFF by default), so production — and ordinary
    // `cargo tauri dev` — builds physically lack this route. Even when the
    // feature is enabled, the handler still requires the runtime env gate
    // (OLYMPUS_ENV=development + OLYMPUS_ALLOW_DEV_SIGNING_KEY_BOOTSTRAP=1).
    #[cfg(feature = "dev-signing-route")]
    let router = router.route("/key/signing/dev-generate", post(dev_generate_signing_key));

    router
}
