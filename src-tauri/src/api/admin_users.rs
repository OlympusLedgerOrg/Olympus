//! Admin user-management routes.
//!
//! Gated by [`require_admin_auth`] — accepts either the operator-only
//! `OLYMPUS_ADMIN_KEY` env var (sent via the `x-admin-key` header) OR a
//! regular API key whose owning user has `role = 'admin'` and whose
//! scope set contains `admin`. The dual path eliminates a second root
//! credential with divergent policy; normal API-key revocation and role
//! demotion both immediately revoke admin access. Lets the operator:
//!
//! * `GET /admin/users` — list users + their key scopes (no raw keys).
//! * `POST /admin/users/{user_id}/keys` — mint a fresh API key with
//!   chosen scopes. Raw key returned ONCE.
//! * `PATCH /admin/keys/{key_id}/scopes` — update an existing key's
//!   scope set.
//! * `DELETE /admin/keys/{key_id}` — soft-revoke a key (stamp
//!   `revoked_at`; the row is retained for audit).
//! * `PATCH /admin/users/{user_id}/role` — promote/demote
//!   (`user` / `admin`).
//!
//! Together these eliminate the operator-SQL pattern: any user can be
//! brought up to admin / commit / verify scope from the desktop UI
//! without psql or shell access. The `OLYMPUS_ADMIN_KEY` gate is the
//! root of trust — see [`super::keys::require_admin_key`].

use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    routing::{delete, get, patch, post},
    Json, Router,
};
use chrono::{DateTime, Utc};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::api::middleware::auth::{blake3_key_hash, RateLimit};
use crate::state::AppState;

use crate::zk::proof::fr_to_decimal;

type ApiError = (StatusCode, Json<serde_json::Value>);

fn err(status: StatusCode, detail: &str) -> ApiError {
    (status, Json(json!({ "detail": detail })))
}

/// Log the backend error server-side and return a generic 500 — never
/// reflect raw DB error text on this admin/auth-sensitive surface.
fn db_err(e: sqlx::Error) -> ApiError {
    tracing::error!("admin_users DB error: {e}");
    err(StatusCode::INTERNAL_SERVER_ERROR, "Internal server error.")
}

fn db_or_503(state: &AppState) -> Result<&sqlx::PgPool, ApiError> {
    state
        .pool
        .as_ref()
        .ok_or_else(|| err(StatusCode::SERVICE_UNAVAILABLE, "Database unavailable"))
}

/// Dual-path admin gate — delegates to the single shared implementation
/// in [`crate::api::middleware::auth::require_admin_auth`] so this router
/// and `super::admin` can never drift in their auth policy. Resolves the
/// pool first (503 if the DB is unavailable) and forwards the headers.
///
/// Accepts EITHER the env-gated operator key (`OLYMPUS_ADMIN_KEY` via
/// `x-admin-key`) OR a regular API key whose user has `role = 'admin'`
/// AND the `admin` scope. Demotion or key revocation drops admin access
/// at the next request.
async fn require_admin_auth(state: &AppState, headers: &HeaderMap) -> Result<(), ApiError> {
    let pool = db_or_503(state)?;
    crate::api::middleware::auth::require_admin_auth(headers, pool, &state.bjj_trusted_issuers)
        .await
}

const VALID_SCOPES: &[&str] = &[
    "read", "write", "ingest", "commit", "verify", "prove", "admin",
];

const VALID_ROLES: &[&str] = &["user", "admin"];

fn validate_scopes(scopes: &[String]) -> Result<(), ApiError> {
    let valid: std::collections::HashSet<&str> = VALID_SCOPES.iter().copied().collect();
    let unknown: Vec<&str> = scopes
        .iter()
        .map(String::as_str)
        .filter(|s| !valid.contains(*s))
        .collect();
    if !unknown.is_empty() {
        return Err(err(
            StatusCode::UNPROCESSABLE_ENTITY,
            &format!(
                "Unknown scope(s): {}. Valid: {}",
                unknown.join(", "),
                VALID_SCOPES.join(", ")
            ),
        ));
    }
    Ok(())
}

// ── GET /admin/users ─────────────────────────────────────────────────────────

#[derive(Debug, Serialize, sqlx::FromRow)]
struct UserKeyRow {
    user_id: String,
    email: String,
    role: String,
    plan: String,
    // `users.created_at` and `api_keys.created_at` are TIMESTAMPTZ in
    // the schema (migration 0010) — decode as DateTime<Utc>, not
    // NaiveDateTime, otherwise sqlx errors with a mismatched-type
    // panic that surfaces as a 500 on every GET /admin/users.
    user_created_at: DateTime<Utc>,
    key_id: Option<String>,
    key_name: Option<String>,
    key_hash_prefix: Option<String>,
    key_scopes: Option<String>,
    key_created_at: Option<DateTime<Utc>>,
}

/// One row per (user, key); users with zero keys appear once with null
/// key fields. Easy to flatten on the frontend.
async fn list_users(
    State(state): State<AppState>,
    headers: HeaderMap,
    _rl: RateLimit,
) -> Result<Json<serde_json::Value>, ApiError> {
    require_admin_auth(&state, &headers).await?;
    let pool = db_or_503(&state)?;

    let rows: Vec<UserKeyRow> = sqlx::query_as(
        "SELECT
             u.id              AS user_id,
             u.email           AS email,
             u.role            AS role,
             u.plan            AS plan,
             u.created_at      AS user_created_at,
             k.id              AS key_id,
             k.name            AS key_name,
             SUBSTRING(k.key_hash FOR 12) AS key_hash_prefix,
             k.scopes          AS key_scopes,
             k.created_at      AS key_created_at
         FROM users u
         LEFT JOIN api_keys k ON k.user_id = u.id
         ORDER BY u.created_at DESC, k.created_at ASC",
    )
    .fetch_all(pool)
    .await
    .map_err(db_err)?;

    Ok(Json(json!({ "rows": rows })))
}

// ── POST /admin/users/{user_id}/keys ────────────────────────────────────────

#[derive(Debug, Deserialize)]
struct MintKeyRequest {
    name: String,
    scopes: Vec<String>,
}

#[derive(Debug, Serialize)]
struct MintKeyResponse {
    /// Raw key — shown ONCE. Caller must save it now.
    raw_key: String,
    key_id: String,
    user_id: String,
    name: String,
    scopes: Vec<String>,
    key_hash: String,
    /// The Baby Jubjub private key the api_key is derived from.
    /// Holders should treat THIS as the master secret — if they lose
    /// `raw_key` but keep `bjj_private_key_hex`, they can re-derive
    /// the API key client-side. Losing both is unrecoverable.
    bjj_private_key_hex: String,
    /// The matching pubkey (also stored in `api_keys.bjj_pubkey_*` so
    /// the server can identify the BJJ identity behind any request
    /// authenticated by this api_key).
    bjj_pubkey_x: String,
    bjj_pubkey_y: String,
}

async fn mint_key_for_user(
    State(state): State<AppState>,
    headers: HeaderMap,
    _rl: RateLimit,
    Path(user_id): Path<String>,
    Json(body): Json<MintKeyRequest>,
) -> Result<Json<MintKeyResponse>, ApiError> {
    require_admin_auth(&state, &headers).await?;
    let pool = db_or_503(&state)?;

    if body.name.trim().is_empty() {
        return Err(err(
            StatusCode::UNPROCESSABLE_ENTITY,
            "name must be non-empty",
        ));
    }
    validate_scopes(&body.scopes)?;

    // Confirm the user exists; surface a clear 404 instead of an opaque
    // foreign-key violation.
    let exists: Option<(String,)> = sqlx::query_as("SELECT id FROM users WHERE id = $1")
        .bind(&user_id)
        .fetch_optional(pool)
        .await
        .map_err(db_err)?;
    if exists.is_none() {
        return Err(err(StatusCode::NOT_FOUND, "user not found"));
    }

    // v0.9 "one master key" unification: every minted API key is now
    // tied to a fresh Baby Jubjub keypair. The api_key is *derived*
    // from the BJJ private key (see derive_api_key_from_bjj), so the
    // recipient has a single secret to keep. We persist the BJJ
    // pubkey on the row so the server can identify the BJJ identity
    // behind any request authed with this api_key — that's the hook
    // for SBT-based capability resolution downstream.
    // `Zeroizing` wipes the private-key bytes on every exit path (success,
    // early-return error, or panic) — the only intentional copy that
    // survives is the hex string returned to the caller below.
    let mut bjj_priv = zeroize::Zeroizing::new([0u8; 32]);
    rand::thread_rng().fill_bytes(&mut *bjj_priv);
    let bjj_pubkey = crate::zk::witness::baby_jubjub::BabyJubJubPubKey::from_private(&bjj_priv)
        .map_err(|e| {
            tracing::error!("BJJ pubkey derive failed: {e}");
            err(StatusCode::INTERNAL_SERVER_ERROR, "Internal server error.")
        })?;
    let raw_key = crate::api::middleware::auth::derive_api_key_from_bjj(&bjj_priv);
    let key_hash = blake3_key_hash(&raw_key);
    let key_id = uuid::Uuid::new_v4().to_string();
    let scopes_json = serde_json::to_string(&body.scopes).expect("Vec<String> always serialises");
    let pubkey_x = fr_to_decimal(&bjj_pubkey.x);
    let pubkey_y = fr_to_decimal(&bjj_pubkey.y);

    sqlx::query(
        "INSERT INTO api_keys
             (id, user_id, key_hash, name, scopes, created_at,
              bjj_pubkey_x, bjj_pubkey_y)
         VALUES ($1, $2, $3, $4, $5, NOW(), $6, $7)",
    )
    .bind(&key_id)
    .bind(&user_id)
    .bind(&key_hash)
    .bind(&body.name)
    .bind(&scopes_json)
    .bind(&pubkey_x)
    .bind(&pubkey_y)
    .execute(pool)
    .await
    .map_err(db_err)?;

    Ok(Json(MintKeyResponse {
        raw_key,
        bjj_private_key_hex: hex::encode(*bjj_priv),
        bjj_pubkey_x: pubkey_x,
        bjj_pubkey_y: pubkey_y,
        key_id,
        user_id,
        name: body.name,
        scopes: body.scopes,
        key_hash,
    }))
}

// ── PATCH /admin/keys/{key_id}/scopes ───────────────────────────────────────

#[derive(Debug, Deserialize)]
struct UpdateScopesRequest {
    scopes: Vec<String>,
}

async fn update_key_scopes(
    State(state): State<AppState>,
    headers: HeaderMap,
    _rl: RateLimit,
    Path(key_id): Path<String>,
    Json(body): Json<UpdateScopesRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    require_admin_auth(&state, &headers).await?;
    let pool = db_or_503(&state)?;
    validate_scopes(&body.scopes)?;

    let scopes_json = serde_json::to_string(&body.scopes).expect("Vec<String> serialises");
    let updated = sqlx::query("UPDATE api_keys SET scopes = $1 WHERE id = $2")
        .bind(&scopes_json)
        .bind(&key_id)
        .execute(pool)
        .await
        .map_err(db_err)?;

    if updated.rows_affected() == 0 {
        return Err(err(StatusCode::NOT_FOUND, "key not found"));
    }
    Ok(Json(
        json!({ "updated": true, "key_id": key_id, "scopes": body.scopes }),
    ))
}

// ── DELETE /admin/keys/{key_id} ─────────────────────────────────────────────

async fn revoke_key(
    State(state): State<AppState>,
    headers: HeaderMap,
    _rl: RateLimit,
    Path(key_id): Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    require_admin_auth(&state, &headers).await?;
    let pool = db_or_503(&state)?;

    // Soft-revoke: the auth extractors gate on `revoked_at IS NULL`, so
    // stamping the column immediately drops the key's access while
    // preserving the row for audit (which key existed, its scopes, when
    // it was revoked). A hard DELETE would erase that history.
    let revoked = sqlx::query("UPDATE api_keys SET revoked_at = NOW() WHERE id = $1")
        .bind(&key_id)
        .execute(pool)
        .await
        .map_err(db_err)?;
    if revoked.rows_affected() == 0 {
        return Err(err(StatusCode::NOT_FOUND, "key not found"));
    }
    Ok(Json(json!({ "revoked": true, "key_id": key_id })))
}

// ── PATCH /admin/users/{user_id}/role ───────────────────────────────────────

#[derive(Debug, Deserialize)]
struct UpdateRoleRequest {
    role: String,
}

async fn update_user_role(
    State(state): State<AppState>,
    headers: HeaderMap,
    _rl: RateLimit,
    Path(user_id): Path<String>,
    Json(body): Json<UpdateRoleRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    require_admin_auth(&state, &headers).await?;
    let pool = db_or_503(&state)?;

    if !VALID_ROLES.contains(&body.role.as_str()) {
        return Err(err(
            StatusCode::UNPROCESSABLE_ENTITY,
            &format!("role must be one of: {}", VALID_ROLES.join(", ")),
        ));
    }

    // Self-lockout guard: refuse to demote the last remaining admin, which would
    // remove all DB-backed admin access to the UI. The env OLYMPUS_ADMIN_KEY path
    // stays as an independent recovery root, but losing the UI admin silently is
    // a sharp edge worth blocking.
    if body.role != "admin" {
        let other_admins: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM users WHERE role = 'admin' AND id <> $1")
                .bind(&user_id)
                .fetch_one(pool)
                .await
                .map_err(db_err)?;
        if other_admins == 0 {
            return Err(err(
                StatusCode::CONFLICT,
                "cannot demote the last remaining admin (UI recovery would require OLYMPUS_ADMIN_KEY)",
            ));
        }
    }

    let updated = sqlx::query("UPDATE users SET role = $1 WHERE id = $2")
        .bind(&body.role)
        .bind(&user_id)
        .execute(pool)
        .await
        .map_err(db_err)?;
    if updated.rows_affected() == 0 {
        return Err(err(StatusCode::NOT_FOUND, "user not found"));
    }
    Ok(Json(
        json!({ "updated": true, "user_id": user_id, "role": body.role }),
    ))
}

// ── Router ──────────────────────────────────────────────────────────────────

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/admin/users", get(list_users))
        .route("/admin/users/{user_id}/keys", post(mint_key_for_user))
        .route("/admin/users/{user_id}/role", patch(update_user_role))
        .route("/admin/keys/{key_id}/scopes", patch(update_key_scopes))
        .route("/admin/keys/{key_id}", delete(revoke_key))
}
