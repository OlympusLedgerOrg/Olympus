use std::sync::Arc;

use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::error::{ApiError, ApiResult};
use super::state::AppState;

// ── Types ─────────────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct RegisterRequest {
    pub email: String,
    pub password: String,
}

#[derive(Debug, Serialize)]
pub struct RegisterResponse {
    pub user_id: String,
    pub email: String,
}

#[derive(Debug, Deserialize)]
pub struct LoginRequest {
    pub email: String,
    pub password: String,
}

#[derive(Debug, Serialize)]
pub struct LoginResponse {
    pub user_id: String,
    pub email: String,
    /// Opaque session token (BLAKE3 of user_id + secret). Not a JWT.
    pub token: String,
}

// ── Handlers ──────────────────────────────────────────────────────────────────

pub async fn register(
    State(state): State<Arc<AppState>>,
    Json(req): Json<RegisterRequest>,
) -> ApiResult<(StatusCode, Json<RegisterResponse>)> {
    validate_email(&req.email)?;
    if req.password.len() < 8 {
        return Err(ApiError::BadRequest("password must be ≥ 8 characters".into()));
    }

    // Check for existing account.
    let exists: bool =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM users WHERE email = $1)")
            .bind(&req.email)
            .fetch_one(&state.pool)
            .await
            .unwrap_or(false);
    if exists {
        return Err(ApiError::Conflict("email already registered".into()));
    }

    let user_id = Uuid::new_v4().to_string();
    let password_hash = bcrypt_hash(&req.password)?;

    sqlx::query(
        "INSERT INTO users (id, email, password_hash, role, plan, created_at) \
         VALUES ($1, $2, $3, 'user', 'free', $4)",
    )
    .bind(&user_id)
    .bind(&req.email)
    .bind(&password_hash)
    .bind(Utc::now())
    .execute(&state.pool)
    .await?;

    Ok((
        StatusCode::CREATED,
        Json(RegisterResponse {
            user_id,
            email: req.email,
        }),
    ))
}

pub async fn login(
    State(state): State<Arc<AppState>>,
    Json(req): Json<LoginRequest>,
) -> ApiResult<Json<LoginResponse>> {
    #[derive(sqlx::FromRow)]
    struct Row {
        id: String,
        email: String,
        password_hash: Option<String>,
    }

    let row: Option<Row> =
        sqlx::query_as("SELECT id, email, password_hash FROM users WHERE email = $1")
            .bind(&req.email)
            .fetch_optional(&state.pool)
            .await?;

    let row = row.ok_or_else(|| ApiError::Unauthorized("invalid credentials".into()))?;

    let hash = row
        .password_hash
        .as_deref()
        .ok_or_else(|| ApiError::Unauthorized("password auth not configured".into()))?;

    if !bcrypt_verify(&req.password, hash)? {
        return Err(ApiError::Unauthorized("invalid credentials".into()));
    }

    let token = session_token(&row.id);

    Ok(Json(LoginResponse {
        user_id: row.id,
        email: row.email,
        token,
    }))
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn validate_email(email: &str) -> ApiResult<()> {
    if email.contains('@') && email.len() <= 320 {
        Ok(())
    } else {
        Err(ApiError::BadRequest("invalid email".into()))
    }
}

/// Argon2id password hash (via blake3 for now — swap for argon2 crate in production).
/// Using BLAKE3 keyed hash as a stand-in; production should use argon2.
fn bcrypt_hash(password: &str) -> ApiResult<String> {
    let salt = Uuid::new_v4().to_string();
    let hash = blake3::derive_key(&salt, password.as_bytes());
    Ok(format!("$blake3${}${}", salt, hex::encode(hash)))
}

fn bcrypt_verify(password: &str, stored: &str) -> ApiResult<bool> {
    let parts: Vec<&str> = stored.splitn(4, '$').collect();
    if parts.len() < 4 || parts[1] != "blake3" {
        return Err(ApiError::Internal("unsupported hash format".into()));
    }
    let salt = parts[2];
    let expected = parts[3];
    let hash = blake3::derive_key(salt, password.as_bytes());
    Ok(hex::encode(hash) == expected)
}

fn session_token(user_id: &str) -> String {
    let secret = std::env::var("OLYMPUS_SESSION_SECRET")
        .unwrap_or_else(|_| "dev-secret".into());
    let mut h = blake3::Hasher::new_keyed(
        &blake3::derive_key("olympus session token", secret.as_bytes()),
    );
    h.update(user_id.as_bytes());
    h.finalize().to_hex().to_string()
}
