//! User authentication and API key management — port of `api/routers/user_auth.py`.
//!
//! Routes
//! ------
//! POST   /auth/register               — create account + first API key
//! POST   /auth/login                  — password → list of active API keys
//! POST   /auth/reissue-key            — email + password → fresh key (no existing key needed)
//! POST   /auth/keys                   — issue additional key (requires auth)
//! GET    /auth/keys                   — list caller's active keys
//! DELETE /auth/keys/{key_id}          — revoke a key
//! DELETE /auth/me                     — self-delete account (email + password, no key needed)
//! POST   /auth/admin/users            — admin: create user with chosen scopes
//! DELETE /auth/admin/users/{user_id}  — admin: delete any user + their keys
//! POST   /auth/recovery/request       — issue a single-use password-recovery token
//! POST   /auth/recovery/complete      — consume token, reset password, issue new key
//!
//! # Password hashing
//!
//! Identical format to `api/routers/user_auth.py`:
//! `scrypt$<N>$<r>$<p>$<salt_hex>$<dk_hex>`
//! where N=16384, r=8, p=1, output=64 bytes.  Cross-compatible: a hash
//! produced by Python can be verified here and vice-versa.
//!
//! # Key hashing
//!
//! Raw keys are 32-byte CSPRNG output hex-encoded (64 hex chars).
//! The stored `key_hash` is `BLAKE3(raw_key_string.as_bytes()).hex()`,
//! matching `_hash_key` in `api/auth.py`.
//!
//! # Module layout (pure code-motion split)
//!
//! - [`types`]    — DB row structs, request/response schemas, serde defaults
//! - [`helpers`]  — constants, error helpers, scope-policy validation, email
//!   normalisation, registration-approval HMAC, DB write helpers
//! - [`handlers`] — account/key/admin route handlers
//! - [`recovery`] — password-recovery route handlers
//! - [`crypto`]   — scrypt password hashing + raw-key generation (pre-existing)

use axum::{
    routing::{delete, post},
    Router,
};

use crate::state::AppState;

mod crypto;
mod handlers;
mod helpers;
mod recovery;
mod types;

#[cfg(test)]
mod tests;

// Re-export the previously-public surface at the same paths so no other file
// in the repo needs its imports changed.
pub use types::{
    AdminRegisterRequest, AdminRegisterResponse, DeleteAccountRequest, KeyCreateRequest,
    KeyCreateResponse, KeyInfo, LoginRequest, LoginResponse, RecoveryCompleteRequest,
    RecoveryRequest, RecoveryRequestResponse, RegisterRequest, RegisterResponse, ReissueKeyRequest,
};

// ── Router ────────────────────────────────────────────────────────────────────

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/auth/register", post(handlers::register))
        .route("/auth/login", post(handlers::login))
        .route("/auth/reissue-key", post(handlers::reissue_key))
        .route(
            "/auth/keys",
            post(handlers::create_key).get(handlers::list_keys),
        )
        .route("/auth/keys/{key_id}", delete(handlers::revoke_key))
        .route("/auth/me", delete(handlers::delete_own_account))
        .route("/auth/admin/users", post(handlers::admin_create_user))
        .route(
            "/auth/admin/users/{user_id}",
            delete(handlers::admin_delete_user),
        )
        .route("/auth/recovery/request", post(recovery::request_recovery))
        .route("/auth/recovery/complete", post(recovery::complete_recovery))
}
