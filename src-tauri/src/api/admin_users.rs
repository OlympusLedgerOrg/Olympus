//! Admin user-management routes.
//!
//! Gated by the operator-only `OLYMPUS_ADMIN_KEY` env var (sent via the
//! `x-admin-key` header). Lets the operator:
//!
//! * `GET /admin/users` — list users + their key scopes (no raw keys).
//! * `POST /admin/users/{user_id}/keys` — mint a fresh API key with
//!   chosen scopes. Raw key returned ONCE.
//! * `PATCH /admin/keys/{key_id}/scopes` — update an existing key's
//!   scope set.
//! * `DELETE /admin/keys/{key_id}` — revoke a key (DELETE row).
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
use chrono::NaiveDateTime;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::api::middleware::auth::{blake3_key_hash, RateLimit};
use crate::state::AppState;

type ApiError = (StatusCode, Json<serde_json::Value>);

fn err(status: StatusCode, detail: &str) -> ApiError {
    (status, Json(json!({ "detail": detail })))
}

fn db_or_503(state: &AppState) -> Result<&sqlx::PgPool, ApiError> {
    state
        .pool
        .as_ref()
        .ok_or_else(|| err(StatusCode::SERVICE_UNAVAILABLE, "Database unavailable"))
}

/// Same gate as `/key/admin/generate` — requires `OLYMPUS_ADMIN_KEY` set
/// and the matching `x-admin-key` header. Constant-time comparison.
fn require_admin_key(headers: &HeaderMap) -> Result<(), ApiError> {
    use subtle::ConstantTimeEq;
    let admin_key = std::env::var("OLYMPUS_ADMIN_KEY").unwrap_or_default();
    if admin_key.is_empty() {
        return Err(err(
            StatusCode::SERVICE_UNAVAILABLE,
            "Admin key not configured. Set OLYMPUS_ADMIN_KEY to enable.",
        ));
    }
    let provided = headers
        .get("x-admin-key")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if !bool::from(provided.as_bytes().ct_eq(admin_key.as_bytes())) {
        return Err(err(StatusCode::UNAUTHORIZED, "Invalid admin key."));
    }
    Ok(())
}

const VALID_SCOPES: &[&str] =
    &["read", "write", "ingest", "commit", "verify", "prove", "admin"];

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
    user_created_at: NaiveDateTime,
    key_id: Option<String>,
    key_name: Option<String>,
    key_hash_prefix: Option<String>,
    key_scopes: Option<String>,
    key_created_at: Option<NaiveDateTime>,
}

/// One row per (user, key); users with zero keys appear once with null
/// key fields. Easy to flatten on the frontend.
async fn list_users(
    State(state): State<AppState>,
    headers: HeaderMap,
    _rl: RateLimit,
) -> Result<Json<serde_json::Value>, ApiError> {
    require_admin_key(&headers)?;
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
    .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, &format!("DB: {e}")))?;

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
}

async fn mint_key_for_user(
    State(state): State<AppState>,
    headers: HeaderMap,
    _rl: RateLimit,
    Path(user_id): Path<String>,
    Json(body): Json<MintKeyRequest>,
) -> Result<Json<MintKeyResponse>, ApiError> {
    require_admin_key(&headers)?;
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
        .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, &format!("DB: {e}")))?;
    if exists.is_none() {
        return Err(err(StatusCode::NOT_FOUND, "user not found"));
    }

    // Generate 32 random bytes → 64-char hex key prefixed with `oly_`
    // (matches the bootstrap key shape).
    let mut raw_bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut raw_bytes);
    let raw_key = format!("oly_{}", hex::encode(raw_bytes));
    let key_hash = blake3_key_hash(&raw_key);
    let key_id = uuid::Uuid::new_v4().to_string();
    let scopes_json = serde_json::to_string(&body.scopes).expect("Vec<String> always serialises");

    sqlx::query(
        "INSERT INTO api_keys (id, user_id, key_hash, name, scopes, created_at)
         VALUES ($1, $2, $3, $4, $5, NOW())",
    )
    .bind(&key_id)
    .bind(&user_id)
    .bind(&key_hash)
    .bind(&body.name)
    .bind(&scopes_json)
    .execute(pool)
    .await
    .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, &format!("DB: {e}")))?;

    Ok(Json(MintKeyResponse {
        raw_key,
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
    require_admin_key(&headers)?;
    let pool = db_or_503(&state)?;
    validate_scopes(&body.scopes)?;

    let scopes_json = serde_json::to_string(&body.scopes).expect("Vec<String> serialises");
    let updated = sqlx::query("UPDATE api_keys SET scopes = $1 WHERE id = $2")
        .bind(&scopes_json)
        .bind(&key_id)
        .execute(pool)
        .await
        .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, &format!("DB: {e}")))?;

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
    require_admin_key(&headers)?;
    let pool = db_or_503(&state)?;

    let deleted = sqlx::query("DELETE FROM api_keys WHERE id = $1")
        .bind(&key_id)
        .execute(pool)
        .await
        .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, &format!("DB: {e}")))?;
    if deleted.rows_affected() == 0 {
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
    require_admin_key(&headers)?;
    let pool = db_or_503(&state)?;

    if !VALID_ROLES.contains(&body.role.as_str()) {
        return Err(err(
            StatusCode::UNPROCESSABLE_ENTITY,
            &format!("role must be one of: {}", VALID_ROLES.join(", ")),
        ));
    }
    let updated = sqlx::query("UPDATE users SET role = $1 WHERE id = $2")
        .bind(&body.role)
        .bind(&user_id)
        .execute(pool)
        .await
        .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, &format!("DB: {e}")))?;
    if updated.rows_affected() == 0 {
        return Err(err(StatusCode::NOT_FOUND, "user not found"));
    }
    Ok(Json(json!({ "updated": true, "user_id": user_id, "role": body.role })))
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
