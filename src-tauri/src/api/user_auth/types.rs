//! DB row types, request/response schemas, and serde defaults for the
//! user-auth module. Pure data — no handlers or policy logic.

use chrono::{DateTime, NaiveDateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use axum::http::StatusCode;

use super::helpers::{
    err, ApiError, DEFAULT_EXPIRY_DAYS, KEY_DEFAULT_SCOPES, REGISTER_DEFAULT_SCOPES,
};

// ── DB row types ──────────────────────────────────────────────────────────────

#[derive(sqlx::FromRow)]
pub(super) struct UserRow {
    pub(super) id: Uuid,
    pub(super) email: String,
    pub(super) password_hash: String,
    pub(super) role: String,
    // `users.created_at` is TIMESTAMPTZ (migration 0010); sqlx 0.9 refuses
    // to decode TIMESTAMPTZ into `NaiveDateTime` and the whole query 500s
    // (same mismatch documented in `admin_users.rs::UserKeyRow`). Decode as
    // `DateTime<Utc>`.
    #[allow(dead_code)]
    pub(super) created_at: DateTime<Utc>,
}

#[derive(sqlx::FromRow)]
pub(super) struct ApiKeyRow {
    // `api_keys.id` / `user_id` are VARCHAR(36) (migration 0010), so every
    // SELECT below casts them `id::uuid, user_id::uuid` to decode into
    // `Uuid` — and every WHERE that compares them to a bound `Uuid` casts
    // the placeholder `$n::text`. `expires_at` / `created_at` / `revoked_at`
    // are TIMESTAMPTZ, which sqlx 0.9 will only decode into `DateTime<Utc>`
    // (decoding into `NaiveDateTime` 500s — same mismatch documented in
    // `admin_users.rs::UserKeyRow`).
    pub(super) id: Uuid,
    #[allow(dead_code)]
    pub(super) user_id: Uuid,
    pub(super) name: String,
    pub(super) scopes: String,
    pub(super) expires_at: DateTime<Utc>,
    pub(super) created_at: DateTime<Utc>,
    pub(super) revoked_at: Option<DateTime<Utc>>,
}

#[derive(sqlx::FromRow)]
pub(super) struct RecoveryTokenRow {
    pub(super) user_id: Uuid,
}

// ── Schemas ───────────────────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct RegisterRequest {
    pub email: String,
    pub password: String,
    #[serde(default = "default_key_name")]
    pub name: String,
    #[serde(default = "register_default_scopes")]
    pub scopes: Vec<String>,
    #[serde(default = "default_expiry")]
    pub expires_at: String,
}

#[derive(Deserialize)]
pub struct AdminRegisterRequest {
    pub email: String,
    pub password: String,
    #[serde(default = "default_key_name")]
    pub name: String,
    #[serde(default = "register_default_scopes")]
    pub scopes: Vec<String>,
    #[serde(default = "default_expiry")]
    pub expires_at: String,
    #[serde(default = "default_role")]
    pub role: String,
}

#[derive(Deserialize)]
pub struct LoginRequest {
    pub email: String,
    pub password: String,
}

#[derive(Deserialize)]
pub struct KeyCreateRequest {
    #[serde(default = "default_key_name")]
    pub name: String,
    #[serde(default = "key_default_scopes")]
    pub scopes: Vec<String>,
    #[serde(default = "default_expiry")]
    pub expires_at: String,
}

#[derive(Deserialize)]
pub struct ReissueKeyRequest {
    pub email: String,
    pub password: String,
    #[serde(default = "register_default_scopes")]
    pub scopes: Vec<String>,
}

#[derive(Deserialize)]
pub struct DeleteAccountRequest {
    pub email: String,
    pub password: String,
}

#[derive(Deserialize)]
pub struct RecoveryRequest {
    pub email: String,
}

#[derive(Deserialize)]
pub struct RecoveryCompleteRequest {
    pub token: String,
    pub new_password: String,
    #[serde(default = "register_default_scopes")]
    pub scopes: Vec<String>,
    #[serde(default = "default_true")]
    pub revoke_existing_keys: bool,
}

pub(super) fn default_key_name() -> String {
    "default".to_owned()
}
pub(super) fn register_default_scopes() -> Vec<String> {
    REGISTER_DEFAULT_SCOPES
        .iter()
        .map(|s| s.to_string())
        .collect()
}
pub(super) fn key_default_scopes() -> Vec<String> {
    KEY_DEFAULT_SCOPES.iter().map(|s| s.to_string()).collect()
}
pub(super) fn default_expiry() -> String {
    let now = chrono::Utc::now();
    let exp = now + chrono::Duration::days(DEFAULT_EXPIRY_DAYS);
    exp.format("%Y-%m-%dT%H:%M:%SZ").to_string()
}
pub(super) fn default_role() -> String {
    "user".to_owned()
}
pub(super) fn default_true() -> bool {
    true
}

// ── Response types ────────────────────────────────────────────────────────────

#[derive(Serialize)]
pub struct RegisterResponse {
    pub user_id: Uuid,
    pub email: String,
    pub api_key: String,
    pub key_id: Uuid,
    pub scopes: Vec<String>,
}

#[derive(Serialize)]
pub struct AdminRegisterResponse {
    pub user_id: Uuid,
    pub email: String,
    pub api_key: String,
    pub key_id: Uuid,
    pub scopes: Vec<String>,
    pub role: String,
}

#[derive(Serialize)]
pub struct KeyInfo {
    pub id: Uuid,
    pub name: String,
    pub scopes: Vec<String>,
    pub expires_at: String,
    pub created_at: String,
    pub revoked: bool,
}

#[derive(Serialize)]
pub struct LoginResponse {
    pub user_id: Uuid,
    pub email: String,
    pub keys: Vec<KeyInfo>,
}

#[derive(Serialize)]
pub struct KeyCreateResponse {
    pub api_key: String,
    pub key_id: Uuid,
    pub name: String,
    pub scopes: Vec<String>,
    pub expires_at: String,
}

#[derive(Serialize)]
pub struct RecoveryRequestResponse {
    pub detail: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recovery_token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<String>,
}
pub(super) fn parse_expires(s: &str) -> Result<NaiveDateTime, ApiError> {
    // Accept ISO 8601 with optional trailing Z.
    let normalised = s.replace('Z', "+00:00");
    chrono::DateTime::parse_from_rfc3339(&normalised)
        .map(|dt| dt.naive_utc())
        .map_err(|_| {
            err(
                StatusCode::UNPROCESSABLE_ENTITY,
                &format!("Invalid expires_at: {s:?}"),
            )
        })
}
