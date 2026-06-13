//! Olympus-native Soulbound Tokens (SBTs).
//!
//! Every credential row is BJJ-EdDSA-signed by the federation authority
//! key at issue time and (when revoked) again at revocation time. Anyone
//! holding the federation BJJ public key can re-verify the credential
//! offline — no contact with the Olympus node required, no blockchain.
//!
//! Wire shape
//! ----------
//! A credential is uniquely identified by `commit_id`:
//!
//! ```text
//! commit_id = BLAKE3(
//!     "OLY:SBT:V1"
//!     | len(holder_key) || holder_key
//!     | len(credential_type) || credential_type
//!     | issued_at_unix (BE i64)
//!     | len(details_canonical_json) || details_canonical_json
//! )
//! ```
//!
//! `details` is canonicalised with RFC 8785 JCS (via the `olympus-crypto`
//! `canonical` module), so any conformant JCS implementation reproduces the
//! same bytes regardless of field ordering. The signature is over the
//! commit_id reinterpreted as a BN254 `Fr` field element (via
//! `from_le_bytes_mod_order`), which is the same domain the in-circuit
//! verifier expects.
//!
//! Routes
//! ------
//! * `POST /credentials` — issue (scope: admin).
//! * `GET /credentials/{id}` — read with signatures attached.
//! * `GET /credentials?holder=..&type=..` — list, optionally filtered.
//! * `POST /credentials/{id}/revoke` — revoke (admin scope).
//! * `POST /credentials/{id}/verify` — server-side re-verify (debugging
//!   convenience; the real check is offline against the BJJ pubkey).
//!
//! Module layout (pure code-motion split, no behavioral change):
//! * [`issue`] — `POST /credentials` (plaintext / Pedersen-commit / quorum)
//! * [`read`] — `GET /credentials` + `GET /credentials/{id}`
//! * [`revoke`] — `POST /credentials/{id}/revoke`
//! * [`verify`] — `POST /credentials/{id}/verify`
//! * [`quorum`] — quorum-issuance support (signer set, co-sign, ZK proof)
//! * [`crypto`] — commit-id / revoke-digest construction (domain separation)
//! * [`types`] — `CredentialRow` / `CredentialView`

use axum::{
    http::StatusCode,
    routing::{get, post},
    Json, Router,
};
use serde_json::json;

use crate::api::middleware::auth::AuthenticatedKey;
use crate::state::AppState;

type ApiError = (StatusCode, Json<serde_json::Value>);

fn err(status: StatusCode, detail: &str) -> ApiError {
    (status, Json(json!({ "detail": detail })))
}

/// Log a DB error internally and return a generic message to the client —
/// avoids leaking driver/schema internals (audit TOB-OLY-07).
fn db_err(e: impl std::fmt::Display) -> ApiError {
    tracing::error!("credentials DB error: {e}");
    err(StatusCode::INTERNAL_SERVER_ERROR, "Database error")
}

fn db_or_503(state: &AppState) -> Result<&sqlx::PgPool, ApiError> {
    state
        .pool
        .as_ref()
        .ok_or_else(|| err(StatusCode::SERVICE_UNAVAILABLE, "Database unavailable"))
}

/// Authorize an authority-level credential operation (issue / revoke).
///
/// Audit M-3: credential issuance is the most security-sensitive authority
/// action in the system — an `authority_sbt` minted here itself confers
/// scopes via the SBT scope resolver (`auth::resolve_sbt_scopes`). Gating it
/// on the `admin` *scope* alone let a `role = 'user'` key that had merely
/// been granted the admin scope (directly, or transitively via an
/// `authority_sbt`) mint further authority credentials — a self-bootstrap
/// path. We now additionally require an authority *role* on the owning user,
/// matching the role-AND-scope bar that `require_admin_auth` enforces on the
/// rest of the `/admin/*` surface.
///
/// Accepted roles are `admin` and `system`: `system` is the bootstrap
/// identity surfaced to the desktop operator (it legitimately drives
/// credential issuance — see `bootstrap::ensure_system_api_key`), and
/// `admin` is any operator-promoted user. A plain `role = 'user'` key is
/// refused even if it carries the admin scope. `auth.scopes` already unions
/// the SBT-derived scopes (the `AuthenticatedKey` extractor resolves them),
/// so the scope check here is complete without a second SBT lookup.
async fn require_admin(pool: &sqlx::PgPool, auth: &AuthenticatedKey) -> Result<(), ApiError> {
    if !auth.has_scope("admin") {
        return Err(err(
            StatusCode::FORBIDDEN,
            "API key lacks required scope: 'admin'",
        ));
    }
    // `users.id` is VARCHAR(36) (migration 0010); bind the Uuid and cast the
    // column to text, mirroring the established pattern in `user_auth`.
    let role: Option<String> = sqlx::query_scalar("SELECT role FROM users WHERE id = $1::text")
        .bind(auth.user_id)
        .fetch_optional(pool)
        .await
        .map_err(db_err)?;
    match role.as_deref() {
        Some("admin") | Some("system") => Ok(()),
        _ => Err(err(
            StatusCode::FORBIDDEN,
            "credential operation requires an authority role (admin or system)",
        )),
    }
}

mod crypto;
mod issue;
mod quorum;
mod read;
mod revoke;
mod types;
mod verify;

// Re-export the digest helpers consumed elsewhere in the crate so existing
// `crate::api::credentials::{compute_commit_id, ...}` paths keep resolving
// after the split (bootstrap, federation co-sign, auth, ZK manifest,
// trusted-issuers).
pub(crate) use crypto::parse_fr_decimal;
pub use crypto::{compute_commit_id, compute_commit_id_for_commitment};

use issue::issue_credential;
use read::{get_credential, list_credentials};
use revoke::revoke_credential;
use verify::verify_credential;

// ── Router ──────────────────────────────────────────────────────────────────

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/credentials", post(issue_credential).get(list_credentials))
        .route("/credentials/{id}", get(get_credential))
        .route("/credentials/{id}/revoke", post(revoke_credential))
        .route("/credentials/{id}/verify", post(verify_credential))
}

/// Public transparency subset of credential routes mounted on the federation
/// Tor onion service. Only `POST /credentials/{id}/verify` is exposed — it
/// returns validity booleans, never row contents.
///
/// The credential GETs (`list_credentials`, `get_credential`) are
/// deliberately NOT on the onion service: as of audit M-1 they are
/// admin-scoped (raw rows expose holder keys, issuer pubkeys, signatures and
/// details), so they belong on the local listener only — not the public
/// federation surface. Issuance and revocation are likewise excluded
/// (authority-bound mutations). Mounting only `verify` keeps the Tor surface
/// to genuinely-public transparency.
#[cfg(feature = "federation")]
pub fn public_router() -> Router<AppState> {
    Router::new().route("/credentials/{id}/verify", post(verify_credential))
}
