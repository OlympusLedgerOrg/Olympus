use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::Json;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::auth::AuthedKey;
use super::error::{ApiError, ApiResult};
use super::state::AppState;

// ── Types ─────────────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct CreateKeyRequest {
    pub name: String,
    pub scopes: Vec<String>,
    pub expires_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Serialize)]
pub struct CreateKeyResponse {
    /// The raw API key — shown once, never stored.
    pub key: String,
    pub key_id: String,
    pub name: String,
    pub scopes: Vec<String>,
    pub expires_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Serialize, sqlx::FromRow)]
pub struct KeyRecord {
    pub id: String,
    pub name: String,
    pub scopes: String,
    pub created_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
    pub revoked_at: Option<DateTime<Utc>>,
}

// ── Handlers ──────────────────────────────────────────────────────────────────

/// Create a new API key for the authenticated user's account.
pub async fn create_key(
    State(state): State<Arc<AppState>>,
    authed: AuthedKey,
    Json(req): Json<CreateKeyRequest>,
) -> ApiResult<(StatusCode, Json<CreateKeyResponse>)> {
    authed.require_scope("admin")?;

    let valid_scopes = ["read", "write", "commit", "verify", "ingest", "admin"];
    for scope in &req.scopes {
        if !valid_scopes.contains(&scope.as_str()) {
            return Err(ApiError::BadRequest(format!("unknown scope: {scope}")));
        }
    }

    // Generate a cryptographically random key (32 bytes → 64 hex chars).
    let raw_key = {
        use blake3::Hasher;
        let mut h = Hasher::new();
        h.update(&Uuid::new_v4().as_bytes()[..]);
        h.update(&Uuid::new_v4().as_bytes()[..]);
        h.finalize().to_hex().to_string()
    };

    let key_hash = blake3_hex(&raw_key);
    let key_id = Uuid::new_v4().to_string();
    let now = Utc::now();
    let scopes_str = req.scopes.join(",");

    sqlx::query(
        "INSERT INTO api_keys (id, user_id, key_hash, key_id, name, scopes, expires_at, created_at) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
    )
    .bind(&key_id)
    .bind(&authed.0.key_id) // owner = authenticated caller
    .bind(&key_hash)
    .bind(&key_id)
    .bind(&req.name)
    .bind(&scopes_str)
    .bind(req.expires_at)
    .bind(now)
    .execute(&state.pool)
    .await?;

    Ok((
        StatusCode::CREATED,
        Json(CreateKeyResponse {
            key: raw_key,
            key_id,
            name: req.name,
            scopes: req.scopes,
            expires_at: req.expires_at,
            created_at: now,
        }),
    ))
}

/// List API keys (metadata only — never returns key material).
pub async fn list_keys(
    State(state): State<Arc<AppState>>,
    authed: AuthedKey,
) -> ApiResult<Json<Vec<KeyRecord>>> {
    authed.require_scope("admin")?;

    let keys: Vec<KeyRecord> = sqlx::query_as(
        "SELECT id, name, scopes, created_at, expires_at, revoked_at \
         FROM api_keys WHERE revoked_at IS NULL ORDER BY created_at DESC",
    )
    .fetch_all(&state.pool)
    .await?;

    Ok(Json(keys))
}

/// Revoke an API key by ID.
pub async fn revoke_key(
    State(state): State<Arc<AppState>>,
    authed: AuthedKey,
    Path(key_id): Path<String>,
) -> ApiResult<StatusCode> {
    authed.require_scope("admin")?;

    let rows = sqlx::query(
        "UPDATE api_keys SET revoked_at = NOW() WHERE id = $1 AND revoked_at IS NULL",
    )
    .bind(&key_id)
    .execute(&state.pool)
    .await?
    .rows_affected();

    if rows == 0 {
        Err(ApiError::NotFound(format!("key {key_id}")))
    } else {
        Ok(StatusCode::NO_CONTENT)
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn blake3_hex(s: &str) -> String {
    blake3::hash(s.as_bytes()).to_hex().to_string()
}
