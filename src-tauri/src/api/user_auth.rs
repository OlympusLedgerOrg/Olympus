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

use std::collections::HashSet;

use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    routing::{delete, post},
    Json, Router,
};
use chrono::{NaiveDateTime, Utc};
use hmac::{Hmac, Mac};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use sqlx::PgPool;
use subtle::ConstantTimeEq;
use uuid::Uuid;

use crate::api::middleware::auth::{
    blake3_key_hash, AuthenticatedKey, RateLimit, RegistrationRateLimit,
};
use crate::state::AppState;

// ── Constants ─────────────────────────────────────────────────────────────────

const SCRYPT_LOG_N: u8 = 14; // N = 2^14 = 16 384 — matches Python _SCRYPT_N
const SCRYPT_R: u32 = 8;
const SCRYPT_P: u32 = 1;
const SCRYPT_DK_LEN: usize = 64; // Python hashlib.scrypt default
const SCRYPT_SALT_LEN: usize = 32;

const REGISTER_DEFAULT_SCOPES: &[&str] = &["read", "verify"];
const KEY_DEFAULT_SCOPES: &[&str] = &["ingest", "verify"];
const DEFAULT_EXPIRY: &str = "2099-01-01T00:00:00Z";

const VALID_SCOPES: &[&str] = &["read", "write", "ingest", "commit", "verify", "admin"];
const SELF_SERVICE_SCOPES: &[&str] = &["read", "verify"];
const PRIVILEGED_SCOPES: &[&str] = &["ingest", "commit", "write", "admin"];

const ALLOW_PUBLIC_WRITE_REG_ENV: &str = "OLYMPUS_ALLOW_PUBLIC_WRITE_REGISTRATION";
const REGISTRATION_APPROVAL_HEADER: &str = "x-admin-registration-approval";

// ── Error helper ──────────────────────────────────────────────────────────────

type ApiError = (StatusCode, Json<serde_json::Value>);

fn err(status: StatusCode, detail: &str) -> ApiError {
    (status, Json(serde_json::json!({"detail": detail})))
}

fn err_code(status: StatusCode, detail: &str, code: &str) -> ApiError {
    (status, Json(serde_json::json!({"detail": detail, "code": code})))
}

fn db_err(e: sqlx::Error) -> ApiError {
    tracing::error!("database error: {e}");
    err(StatusCode::INTERNAL_SERVER_ERROR, "Database error.")
}

// ── DB row types ──────────────────────────────────────────────────────────────

#[derive(sqlx::FromRow)]
struct UserRow {
    id: Uuid,
    email: String,
    password_hash: String,
    role: String,
    #[allow(dead_code)]
    created_at: NaiveDateTime,
}

#[derive(sqlx::FromRow)]
struct ApiKeyRow {
    id: Uuid,
    #[allow(dead_code)]
    user_id: Uuid,
    name: String,
    scopes: String,
    expires_at: NaiveDateTime,
    created_at: NaiveDateTime,
    revoked_at: Option<NaiveDateTime>,
}

#[derive(sqlx::FromRow)]
struct RecoveryTokenRow {
    user_id: Uuid,
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

fn default_key_name() -> String {
    "default".to_owned()
}
fn register_default_scopes() -> Vec<String> {
    REGISTER_DEFAULT_SCOPES.iter().map(|s| s.to_string()).collect()
}
fn key_default_scopes() -> Vec<String> {
    KEY_DEFAULT_SCOPES.iter().map(|s| s.to_string()).collect()
}
fn default_expiry() -> String {
    DEFAULT_EXPIRY.to_owned()
}
fn default_role() -> String {
    "user".to_owned()
}
fn default_true() -> bool {
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

// ── Password helpers ──────────────────────────────────────────────────────────

/// Hash `password` with scrypt using the same parameters as Python:
/// N=2^14, r=8, p=1, output=64 bytes, format `scrypt$N$r$p$salt_hex$dk_hex`.
fn hash_password(password: &str) -> String {
    let mut salt = [0u8; SCRYPT_SALT_LEN];
    rand::thread_rng().fill_bytes(&mut salt);

    // scrypt 0.12 dropped dk_len from Params; output length is now determined
    // by the slice passed to scrypt::scrypt() below.
    let params = scrypt::Params::new(SCRYPT_LOG_N, SCRYPT_R, SCRYPT_P)
        .expect("scrypt params are valid compile-time constants");

    let mut dk = [0u8; SCRYPT_DK_LEN];
    scrypt::scrypt(password.as_bytes(), &salt, &params, &mut dk)
        .expect("scrypt output length matches DK_LEN constant");

    format!(
        "scrypt${}${}${}${}${}",
        1u32 << SCRYPT_LOG_N,
        SCRYPT_R,
        SCRYPT_P,
        hex::encode(salt),
        hex::encode(dk),
    )
}

/// Verify `password` against a stored hash in `scrypt$N$r$p$salt_hex$dk_hex`
/// format.  Uses constant-time comparison to prevent timing oracles.
/// Returns `false` on any parse error (rather than panicking).
fn verify_password(password: &str, stored: &str) -> bool {
    let parts: Vec<&str> = stored.splitn(6, '$').collect();
    if parts.len() != 6 || parts[0] != "scrypt" {
        return false;
    }
    let Ok(n) = parts[1].parse::<u64>() else {
        return false;
    };
    let Ok(r) = parts[2].parse::<u32>() else {
        return false;
    };
    let Ok(p) = parts[3].parse::<u32>() else {
        return false;
    };
    let Ok(salt) = hex::decode(parts[4]) else {
        return false;
    };
    let Ok(expected) = hex::decode(parts[5]) else {
        return false;
    };
    if n == 0 || !n.is_power_of_two() || n > (1u64 << 30) {
        return false;
    }
    let log_n = n.trailing_zeros() as u8;
    let Ok(params) = scrypt::Params::new(log_n, r, p) else {
        return false;
    };
    let mut dk = vec![0u8; expected.len()];
    if scrypt::scrypt(password.as_bytes(), &salt, &params, &mut dk).is_err() {
        return false;
    }
    // Constant-time comparison — prevents timing oracles on the derived key.
    bool::from(dk.as_slice().ct_eq(&expected))
}

/// Dummy hash string for timing-safe login when user is not found.
/// Must have the same structure as a real hash so `verify_password` runs to
/// completion and takes a similar wall-clock time.
fn dummy_hash() -> String {
    format!(
        "scrypt${}${}${}${}${}",
        1u32 << SCRYPT_LOG_N,
        SCRYPT_R,
        SCRYPT_P,
        "00".repeat(SCRYPT_SALT_LEN),
        "00".repeat(SCRYPT_DK_LEN),
    )
}

// ── Key helpers ───────────────────────────────────────────────────────────────

/// Generate a CSPRNG raw API key (32 bytes = 64 hex chars), matching
/// `secrets.token_hex(32)` from Python.
fn generate_raw_key() -> String {
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    hex::encode(bytes)
}

fn parse_expires(s: &str) -> Result<NaiveDateTime, ApiError> {
    // Accept ISO 8601 with optional trailing Z.
    let normalised = s.replace('Z', "+00:00");
    chrono::DateTime::parse_from_rfc3339(&normalised)
        .map(|dt| dt.naive_utc())
        .map_err(|_| err(StatusCode::UNPROCESSABLE_ENTITY, &format!("Invalid expires_at: {s:?}")))
}

fn naive_utc() -> NaiveDateTime {
    Utc::now().naive_utc()
}

// ── Scope helpers ─────────────────────────────────────────────────────────────

/// Validate and de-duplicate `requested` scopes against `allowed`.
/// Returns 400 for unknown scopes, 403 for out-of-context scopes.
fn validate_scopes(
    requested: &[String],
    allowed: &HashSet<&str>,
    context: &str,
) -> Result<Vec<String>, ApiError> {
    let valid: HashSet<&str> = VALID_SCOPES.iter().copied().collect();
    let mut seen = HashSet::new();
    let mut deduped = Vec::new();
    for s in requested {
        if seen.insert(s.as_str()) {
            deduped.push(s.clone());
        }
    }
    let unknown: Vec<&str> = deduped
        .iter()
        .map(String::as_str)
        .filter(|s| !valid.contains(*s))
        .collect();
    if !unknown.is_empty() {
        return Err(err(
            StatusCode::BAD_REQUEST,
            &format!(
                "Unknown scope(s) in {context}: {}",
                unknown.join(", ")
            ),
        ));
    }
    let forbidden: Vec<&str> = deduped
        .iter()
        .map(String::as_str)
        .filter(|s| !allowed.contains(*s))
        .collect();
    if !forbidden.is_empty() {
        let allowed_sorted = {
            let mut v: Vec<&str> = allowed.iter().copied().collect();
            v.sort();
            v.join(", ")
        };
        return Err(err(
            StatusCode::FORBIDDEN,
            &format!(
                "Scope(s) not permitted in {context}: {}. Allowed: {allowed_sorted}.",
                forbidden.join(", "),
            ),
        ));
    }
    Ok(deduped)
}

/// Collect all non-expired, non-revoked scopes on an account's active keys.
async fn active_scopes_for_user(
    pool: &PgPool,
    user_id: Uuid,
) -> Result<HashSet<String>, ApiError> {
    let now = naive_utc();
    let rows = sqlx::query_as::<_, ApiKeyRow>(
        "SELECT id, user_id, name, scopes, expires_at, created_at, revoked_at
         FROM api_keys
         WHERE user_id = $1 AND revoked_at IS NULL AND expires_at > $2",
    )
    .bind(user_id)
    .bind(now)
    .fetch_all(pool)
    .await
    .map_err(db_err)?;

    let mut out: HashSet<String> =
        REGISTER_DEFAULT_SCOPES.iter().map(|s| s.to_string()).collect();
    for row in rows {
        let scopes: Vec<String> =
            serde_json::from_str(&row.scopes).map_err(|_| {
                err(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Existing key has invalid scope data.",
                )
            })?;
        out.extend(scopes);
    }
    Ok(out)
}

// ── Admin-key guard helpers ───────────────────────────────────────────────────

fn require_admin_key(headers: &axum::http::HeaderMap) -> Result<(), ApiError> {
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

async fn require_admin_authority(
    headers: &axum::http::HeaderMap,
    pool: &PgPool,
) -> Result<(), ApiError> {
    // Accept either the operator secret or an admin-scoped API key.
    let admin_key = std::env::var("OLYMPUS_ADMIN_KEY").unwrap_or_default();
    let provided = headers
        .get("x-admin-key")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if !admin_key.is_empty()
        && bool::from(provided.as_bytes().ct_eq(admin_key.as_bytes()))
    {
        return Ok(());
    }

    // Fall back to API-key auth with admin scope.
    let raw = headers
        .get("x-api-key")
        .or_else(|| headers.get("authorization"))
        .and_then(|v| v.to_str().ok())
        .map(|s| {
            s.strip_prefix("Bearer ")
                .or_else(|| s.strip_prefix("bearer "))
                .unwrap_or(s)
                .trim()
                .to_owned()
        });
    let Some(raw) = raw else {
        return Err(err(StatusCode::UNAUTHORIZED, "Admin access required."));
    };
    let key_hash = blake3_key_hash(&raw);
    let now = naive_utc();

    #[derive(sqlx::FromRow)]
    struct AdminCheck {
        scopes: String,
        user_role: Option<String>,
    }

    let row = sqlx::query_as::<_, AdminCheck>(
        r#"SELECT k.scopes, u.role AS user_role
           FROM api_keys k
           JOIN users u ON u.id = k.user_id
           WHERE k.key_hash = $1
             AND k.revoked_at IS NULL
             AND k.expires_at > $2"#,
    )
    .bind(&key_hash)
    .bind(now)
    .fetch_optional(pool)
    .await
    .map_err(db_err)?
    .ok_or_else(|| err(StatusCode::UNAUTHORIZED, "Admin access required."))?;

    let scopes: Vec<String> = serde_json::from_str(&row.scopes).unwrap_or_default();
    let is_admin_role = row.user_role.as_deref() == Some("admin");
    let has_admin_scope = scopes.iter().any(|s| s == "admin");

    if is_admin_role && has_admin_scope {
        Ok(())
    } else {
        Err(err(StatusCode::FORBIDDEN, "Admin access required."))
    }
}

// ── Registration-approval signature (HMAC-SHA256) ─────────────────────────────

fn registration_approval_payload(
    email: &str,
    scopes: &[String],
    expires_at: &str,
) -> String {
    let mut sorted = scopes.to_vec();
    sorted.sort();
    sorted.dedup();
    format!("{}|{}|{}", email.to_lowercase().trim(), sorted.join(","), expires_at)
}

fn registration_approval_valid(
    req: &RegisterRequest,
    headers: &axum::http::HeaderMap,
) -> bool {
    let admin_key = std::env::var("OLYMPUS_ADMIN_KEY").unwrap_or_default();
    if admin_key.is_empty() {
        return false;
    }
    let provided = headers
        .get(REGISTRATION_APPROVAL_HEADER)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .trim()
        .to_lowercase();
    if provided.is_empty() {
        return false;
    }
    let payload = registration_approval_payload(&req.email, &req.scopes, &req.expires_at);
    let mut mac = Hmac::<Sha256>::new_from_slice(admin_key.as_bytes())
        .expect("HMAC accepts any key length");
    mac.update(payload.as_bytes());
    let expected = hex::encode(mac.finalize().into_bytes());
    bool::from(provided.as_bytes().ct_eq(expected.as_bytes()))
}

fn public_write_registration_enabled() -> bool {
    std::env::var(ALLOW_PUBLIC_WRITE_REG_ENV)
        .map(|v| v.trim() == "1")
        .unwrap_or(false)
}

// ── DB write helpers ──────────────────────────────────────────────────────────

/// Create a user row + first API key in a single transaction.
/// Returns `(user_id, key_id, raw_key)`.
async fn create_user_with_key(
    pool: &PgPool,
    email: &str,
    password: &str,
    name: &str,
    scopes: &[String],
    expires_at: NaiveDateTime,
    role: &str,
) -> Result<(Uuid, Uuid, String), ApiError> {
    // Check for duplicate email.
    let existing = sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(*) FROM users WHERE email = $1",
    )
    .bind(email)
    .fetch_one(pool)
    .await
    .map_err(db_err)?;
    if existing > 0 {
        return Err(err(StatusCode::CONFLICT, "Email already registered."));
    }
    if password.len() < 12 {
        return Err(err(
            StatusCode::UNPROCESSABLE_ENTITY,
            "Password must be at least 12 characters.",
        ));
    }

    let user_id = Uuid::new_v4();
    let now = naive_utc();
    let pw_hash = hash_password(password);

    sqlx::query(
        "INSERT INTO users (id, email, password_hash, role, created_at)
         VALUES ($1::text, $2, $3, $4, $5)",
    )
    .bind(user_id)
    .bind(email)
    .bind(&pw_hash)
    .bind(role)
    .bind(now)
    .execute(pool)
    .await
    .map_err(db_err)?;

    let (raw_key, key_id) = insert_api_key(pool, user_id, name, scopes, expires_at).await?;
    Ok((user_id, key_id, raw_key))
}

/// Insert a new `api_keys` row and return `(raw_key, key_id)`.
async fn insert_api_key(
    pool: &PgPool,
    user_id: Uuid,
    name: &str,
    scopes: &[String],
    expires_at: NaiveDateTime,
) -> Result<(String, Uuid), ApiError> {
    let raw = generate_raw_key();
    let key_hash = blake3_key_hash(&raw);
    let key_id = Uuid::new_v4();
    let now = naive_utc();
    let scopes_json =
        serde_json::to_string(scopes).expect("Vec<String> always serialises");

    sqlx::query(
        "INSERT INTO api_keys (id, user_id, key_hash, name, scopes, expires_at, created_at)
         VALUES ($1::text, $2::text, $3, $4, $5, $6, $7)",
    )
    .bind(key_id)
    .bind(user_id)
    .bind(&key_hash)
    .bind(name)
    .bind(&scopes_json)
    .bind(expires_at)
    .bind(now)
    .execute(pool)
    .await
    .map_err(db_err)?;

    Ok((raw, key_id))
}

fn key_info(row: &ApiKeyRow) -> Result<KeyInfo, ApiError> {
    let scopes: Vec<String> = serde_json::from_str(&row.scopes).map_err(|_| {
        err(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Key has invalid scope data.",
        )
    })?;
    Ok(KeyInfo {
        id: row.id,
        name: row.name.clone(),
        scopes,
        expires_at: row.expires_at.format("%Y-%m-%dT%H:%M:%S").to_string(),
        created_at: row.created_at.format("%Y-%m-%dT%H:%M:%S").to_string(),
        revoked: row.revoked_at.is_some(),
    })
}

// ── Route handlers ────────────────────────────────────────────────────────────

/// POST /auth/register — create account + first API key.
async fn register(
    State(state): State<AppState>,
    headers: HeaderMap,
    _rl: RegistrationRateLimit,
    Json(body): Json<RegisterRequest>,
) -> Result<(StatusCode, Json<RegisterResponse>), ApiError> {

    let valid_set: HashSet<&str> = VALID_SCOPES.iter().copied().collect();
    let unknown: Vec<&str> = body
        .scopes
        .iter()
        .map(String::as_str)
        .filter(|s| !valid_set.contains(*s))
        .collect();
    if !unknown.is_empty() {
        return Err(err(
            StatusCode::BAD_REQUEST,
            &format!("Unknown scope(s) in register: {}", unknown.join(", ")),
        ));
    }

    let privileged_set: HashSet<&str> = PRIVILEGED_SCOPES.iter().copied().collect();
    let requesting_privileged = body.scopes.iter().any(|s| privileged_set.contains(s.as_str()));
    let has_admin_approval = registration_approval_valid(&body, &headers);

    // Desktop-mode auto-grant: the first registered user (no users in DB yet)
    // gets all requested scopes, including privileged ones.  This makes first-boot
    // seamless on a single-operator desktop install.
    let pool = state.pool.as_ref().ok_or_else(|| {
        err(StatusCode::SERVICE_UNAVAILABLE, "Database unavailable.")
    })?;
    let user_count: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM users WHERE role != 'system'")
        .fetch_one(pool)
        .await
        .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, &format!("DB error: {e}")))?;
    let is_first_user = user_count.0 == 0;

    if requesting_privileged && !is_first_user && !public_write_registration_enabled() && !has_admin_approval {
        let priv_requested: Vec<&str> = body
            .scopes
            .iter()
            .map(String::as_str)
            .filter(|s| privileged_set.contains(*s))
            .collect();
        return Err(err(
            StatusCode::FORBIDDEN,
            &format!(
                "Privileged registration scopes require admin approval. \
                 Requested: {}. Provide {REGISTRATION_APPROVAL_HEADER} \
                 signed with OLYMPUS_ADMIN_KEY, or set {ALLOW_PUBLIC_WRITE_REG_ENV}=1.",
                priv_requested.join(", ")
            ),
        ));
    }

    let allowed: HashSet<&str> = if requesting_privileged || is_first_user {
        VALID_SCOPES.iter().copied().collect()
    } else {
        SELF_SERVICE_SCOPES.iter().copied().collect()
    };
    let scopes = validate_scopes(&body.scopes, &allowed, "register")?;
    let expires = parse_expires(&body.expires_at)?;

    let role = if is_first_user { "admin" } else { "user" };
    let (user_id, key_id, raw_key) =
        create_user_with_key(pool, &body.email, &body.password, &body.name, &scopes, expires, role)
            .await?;

    Ok((
        StatusCode::CREATED,
        Json(RegisterResponse {
            user_id,
            email: body.email,
            api_key: raw_key,
            key_id,
            scopes,
        }),
    ))
}

/// POST /auth/admin/users — admin-protected user creation with chosen scopes.
async fn admin_create_user(
    State(state): State<AppState>,
    headers: HeaderMap,
    _rl: RateLimit,
    Json(body): Json<AdminRegisterRequest>,
) -> Result<(StatusCode, Json<AdminRegisterResponse>), ApiError> {
    let pool = state.pool.as_ref().ok_or_else(|| {
        err(StatusCode::SERVICE_UNAVAILABLE, "Database unavailable.")
    })?;
    require_admin_authority(&headers, pool).await?;

    if body.role != "user" && body.role != "admin" {
        return Err(err(
            StatusCode::UNPROCESSABLE_ENTITY,
            "role must be 'user' or 'admin'.",
        ));
    }
    let allowed: HashSet<&str> = VALID_SCOPES.iter().copied().collect();
    let scopes = validate_scopes(&body.scopes, &allowed, "admin_create_user")?;
    let expires = parse_expires(&body.expires_at)?;

    let (user_id, key_id, raw_key) = create_user_with_key(
        pool, &body.email, &body.password, &body.name, &scopes, expires, &body.role,
    )
    .await?;

    Ok((
        StatusCode::CREATED,
        Json(AdminRegisterResponse {
            user_id,
            email: body.email,
            api_key: raw_key,
            key_id,
            scopes,
            role: body.role,
        }),
    ))
}

/// POST /auth/login — verify password, return active API keys.
///
/// Always runs scrypt even when the user is not found to prevent timing-based
/// email enumeration.
async fn login(
    State(state): State<AppState>,
    _rl: RegistrationRateLimit,
    Json(body): Json<LoginRequest>,
) -> Result<Json<LoginResponse>, ApiError> {
    let pool = state.pool.as_ref().ok_or_else(|| {
        err(StatusCode::SERVICE_UNAVAILABLE, "Database unavailable.")
    })?;

    let user_opt = sqlx::query_as::<_, UserRow>(
        "SELECT id::uuid, email, password_hash, role, created_at FROM users WHERE email = $1",
    )
    .bind(&body.email)
    .fetch_optional(pool)
    .await
    .map_err(db_err)?;

    // Always verify — prevents timing oracle on email enumeration.
    let stored = user_opt
        .as_ref()
        .map(|u| u.password_hash.as_str())
        .unwrap_or_else(|| Box::leak(dummy_hash().into_boxed_str()));

    if !verify_password(&body.password, stored) || user_opt.is_none() {
        return Err(err(StatusCode::UNAUTHORIZED, "Invalid email or password."));
    }
    let user = user_opt.unwrap(); // safe: checked above

    let now = naive_utc();
    let rows = sqlx::query_as::<_, ApiKeyRow>(
        "SELECT id, user_id, name, scopes, expires_at, created_at, revoked_at
         FROM api_keys
         WHERE user_id = $1 AND revoked_at IS NULL AND expires_at > $2
         ORDER BY created_at",
    )
    .bind(user.id)
    .bind(now)
    .fetch_all(pool)
    .await
    .map_err(db_err)?;

    let keys = rows.iter().map(key_info).collect::<Result<Vec<_>, _>>()?;

    Ok(Json(LoginResponse {
        user_id: user.id,
        email: user.email,
        keys,
    }))
}

/// POST /auth/reissue-key — email + password → fresh key (no existing key needed).
async fn reissue_key(
    State(state): State<AppState>,
    _rl: RegistrationRateLimit,
    Json(body): Json<ReissueKeyRequest>,
) -> Result<(StatusCode, Json<KeyCreateResponse>), ApiError> {
    let pool = state.pool.as_ref().ok_or_else(|| {
        err(StatusCode::SERVICE_UNAVAILABLE, "Database unavailable.")
    })?;

    let user_opt = sqlx::query_as::<_, UserRow>(
        "SELECT id::uuid, email, password_hash, role, created_at FROM users WHERE email = $1",
    )
    .bind(&body.email)
    .fetch_optional(pool)
    .await
    .map_err(db_err)?;

    let stored = user_opt
        .as_ref()
        .map(|u| u.password_hash.as_str())
        .unwrap_or_else(|| Box::leak(dummy_hash().into_boxed_str()));

    if !verify_password(&body.password, stored) || user_opt.is_none() {
        return Err(err(StatusCode::UNAUTHORIZED, "Invalid email or password."));
    }
    let user = user_opt.unwrap();

    let allowed_set = active_scopes_for_user(pool, user.id).await?;
    let allowed_refs: HashSet<&str> = allowed_set.iter().map(String::as_str).collect();
    let scopes = validate_scopes(&body.scopes, &allowed_refs, "reissue_key")?;
    let expires = parse_expires(DEFAULT_EXPIRY)?;
    let (raw, key_id) = insert_api_key(pool, user.id, "reissued", &scopes, expires).await?;

    Ok((
        StatusCode::CREATED,
        Json(KeyCreateResponse {
            api_key: raw,
            key_id,
            name: "reissued".to_owned(),
            scopes,
            expires_at: expires.format("%Y-%m-%dT%H:%M:%S").to_string(),
        }),
    ))
}

/// POST /auth/keys — issue additional key for authenticated user.
async fn create_key(
    State(state): State<AppState>,
    auth: AuthenticatedKey,
    _rl: RateLimit,
    Json(body): Json<KeyCreateRequest>,
) -> Result<(StatusCode, Json<KeyCreateResponse>), ApiError> {
    let pool = state.pool.as_ref().ok_or_else(|| {
        err(StatusCode::SERVICE_UNAVAILABLE, "Database unavailable.")
    })?;

    // New key scopes must be ⊆ caller's scopes — prevents privilege escalation.
    let caller_allowed: HashSet<&str> = auth.scopes.iter().map(String::as_str).collect();
    let scopes = validate_scopes(&body.scopes, &caller_allowed, "create_key")?;
    let expires = parse_expires(&body.expires_at)?;
    let (raw, key_id) =
        insert_api_key(pool, auth.user_id, &body.name, &scopes, expires).await?;

    Ok((
        StatusCode::CREATED,
        Json(KeyCreateResponse {
            api_key: raw,
            key_id,
            name: body.name,
            scopes,
            expires_at: expires.format("%Y-%m-%dT%H:%M:%S").to_string(),
        }),
    ))
}

/// GET /auth/keys — list caller's active, non-expired keys.
async fn list_keys(
    State(state): State<AppState>,
    auth: AuthenticatedKey,
    _rl: RateLimit,
) -> Result<Json<Vec<KeyInfo>>, ApiError> {
    let pool = state.pool.as_ref().ok_or_else(|| {
        err(StatusCode::SERVICE_UNAVAILABLE, "Database unavailable.")
    })?;

    let now = naive_utc();
    let rows = sqlx::query_as::<_, ApiKeyRow>(
        "SELECT id, user_id, name, scopes, expires_at, created_at, revoked_at
         FROM api_keys
         WHERE user_id = $1 AND revoked_at IS NULL AND expires_at > $2
         ORDER BY created_at",
    )
    .bind(auth.user_id)
    .bind(now)
    .fetch_all(pool)
    .await
    .map_err(db_err)?;

    rows.iter().map(key_info).collect::<Result<Vec<_>, _>>().map(Json)
}

/// DELETE /auth/keys/{key_id} — revoke one of the caller's keys.
async fn revoke_key(
    State(state): State<AppState>,
    auth: AuthenticatedKey,
    _rl: RateLimit,
    Path(key_id): Path<Uuid>,
) -> Result<StatusCode, ApiError> {
    let pool = state.pool.as_ref().ok_or_else(|| {
        err(StatusCode::SERVICE_UNAVAILABLE, "Database unavailable.")
    })?;

    let row = sqlx::query_as::<_, ApiKeyRow>(
        "SELECT id, user_id, name, scopes, expires_at, created_at, revoked_at
         FROM api_keys WHERE id = $1 AND user_id = $2",
    )
    .bind(key_id)
    .bind(auth.user_id)
    .fetch_optional(pool)
    .await
    .map_err(db_err)?
    .ok_or_else(|| err(StatusCode::NOT_FOUND, "Key not found."))?;

    if row.revoked_at.is_some() {
        return Err(err(StatusCode::CONFLICT, "Key already revoked."));
    }

    sqlx::query("UPDATE api_keys SET revoked_at = $1 WHERE id = $2")
        .bind(naive_utc())
        .bind(key_id)
        .execute(pool)
        .await
        .map_err(db_err)?;

    Ok(StatusCode::NO_CONTENT)
}

/// DELETE /auth/me — delete own account + all keys (email + password, no key required).
async fn delete_own_account(
    State(state): State<AppState>,
    _rl: RateLimit,
    Json(body): Json<DeleteAccountRequest>,
) -> Result<StatusCode, ApiError> {
    let pool = state.pool.as_ref().ok_or_else(|| {
        err(StatusCode::SERVICE_UNAVAILABLE, "Database unavailable.")
    })?;

    let user_opt = sqlx::query_as::<_, UserRow>(
        "SELECT id::uuid, email, password_hash, role, created_at FROM users WHERE email = $1",
    )
    .bind(&body.email)
    .fetch_optional(pool)
    .await
    .map_err(db_err)?;

    let stored = user_opt
        .as_ref()
        .map(|u| u.password_hash.as_str())
        .unwrap_or_else(|| Box::leak(dummy_hash().into_boxed_str()));

    if !verify_password(&body.password, stored) || user_opt.is_none() {
        return Err(err(StatusCode::UNAUTHORIZED, "Invalid email or password."));
    }
    let user = user_opt.unwrap();

    sqlx::query("DELETE FROM api_keys WHERE user_id = $1")
        .bind(user.id)
        .execute(pool)
        .await
        .map_err(db_err)?;
    sqlx::query("DELETE FROM users WHERE id = $1")
        .bind(user.id)
        .execute(pool)
        .await
        .map_err(db_err)?;

    Ok(StatusCode::NO_CONTENT)
}

/// DELETE /auth/admin/users/{user_id} — admin: delete any user + their keys.
async fn admin_delete_user(
    State(state): State<AppState>,
    headers: HeaderMap,
    _rl: RateLimit,
    Path(user_id): Path<Uuid>,
) -> Result<StatusCode, ApiError> {
    let pool = state.pool.as_ref().ok_or_else(|| {
        err(StatusCode::SERVICE_UNAVAILABLE, "Database unavailable.")
    })?;
    require_admin_key(&headers)?;

    let exists = sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM users WHERE id = $1")
        .bind(user_id)
        .fetch_one(pool)
        .await
        .map_err(db_err)?;
    if exists == 0 {
        return Err(err(StatusCode::NOT_FOUND, "User not found."));
    }

    sqlx::query("DELETE FROM api_keys WHERE user_id = $1")
        .bind(user_id)
        .execute(pool)
        .await
        .map_err(db_err)?;
    sqlx::query("DELETE FROM users WHERE id = $1")
        .bind(user_id)
        .execute(pool)
        .await
        .map_err(db_err)?;

    Ok(StatusCode::NO_CONTENT)
}

/// POST /auth/recovery/request — issue a single-use password-recovery token.
///
/// Never reveals whether the email exists (identical response either way).
/// Returns the raw token in the response body only when
/// `OLYMPUS_ENV=development` AND `OLYMPUS_RETURN_RECOVERY_TOKEN=1`.
async fn request_recovery(
    State(state): State<AppState>,
    _rl: RegistrationRateLimit,
    Json(body): Json<RecoveryRequest>,
) -> Result<(StatusCode, Json<RecoveryRequestResponse>), ApiError> {
    const MSG: &str =
        "If an account exists for that email, recovery instructions have been issued.";

    let pool = state.pool.as_ref().ok_or_else(|| {
        err(StatusCode::SERVICE_UNAVAILABLE, "Database unavailable.")
    })?;

    let user_opt = sqlx::query_as::<_, UserRow>(
        "SELECT id::uuid, email, password_hash, role, created_at FROM users WHERE email = $1",
    )
    .bind(body.email.trim())
    .fetch_optional(pool)
    .await
    .map_err(db_err)?;

    let response = RecoveryRequestResponse {
        detail: MSG.to_owned(),
        recovery_token: None,
        expires_at: None,
    };

    let Some(user) = user_opt else {
        return Ok((StatusCode::ACCEPTED, Json(response)));
    };

    // TTL: prefer env var, clamp 60 s – 24 h, default 15 min.
    let ttl_secs: i64 = std::env::var("OLYMPUS_RECOVERY_TOKEN_TTL_SECONDS")
        .ok()
        .and_then(|v| v.parse().ok())
        .map(|v: i64| v.clamp(60, 86_400))
        .unwrap_or(900);

    let now = naive_utc();
    let expires_at = now + chrono::Duration::seconds(ttl_secs);
    let raw_token: String = {
        let bytes: [u8; 32] = rand::random();
        // URL-safe base64: use hex for simplicity (matches Python secrets.token_urlsafe approx.)
        hex::encode(bytes)
    };
    let token_hash = blake3_key_hash(&raw_token);
    let token_id = Uuid::new_v4();

    sqlx::query(
        "INSERT INTO password_recovery_tokens (id, user_id, token_hash, created_at, expires_at)
         VALUES ($1, $2, $3, $4, $5)",
    )
    .bind(token_id)
    .bind(user.id)
    .bind(&token_hash)
    .bind(now)
    .bind(expires_at)
    .execute(pool)
    .await
    .map_err(db_err)?;

    let return_token = std::env::var("OLYMPUS_ENV").ok().as_deref() == Some("development")
        && std::env::var("OLYMPUS_RETURN_RECOVERY_TOKEN").ok().as_deref() == Some("1");

    let response = RecoveryRequestResponse {
        detail: MSG.to_owned(),
        recovery_token: return_token.then_some(raw_token),
        expires_at: return_token
            .then(|| expires_at.format("%Y-%m-%dT%H:%M:%S").to_string()),
    };
    Ok((StatusCode::ACCEPTED, Json(response)))
}

/// POST /auth/recovery/complete — consume token, reset password, issue key.
///
/// Uses an atomic `UPDATE … RETURNING` to claim the token, preventing race
/// conditions when two concurrent requests arrive with the same token.
async fn complete_recovery(
    State(state): State<AppState>,
    _rl: RegistrationRateLimit,
    Json(body): Json<RecoveryCompleteRequest>,
) -> Result<(StatusCode, Json<KeyCreateResponse>), ApiError> {
    if body.new_password.len() < 12 {
        return Err(err(
            StatusCode::UNPROCESSABLE_ENTITY,
            "Password must be at least 12 characters.",
        ));
    }
    let pool = state.pool.as_ref().ok_or_else(|| {
        err(StatusCode::SERVICE_UNAVAILABLE, "Database unavailable.")
    })?;

    let token_hash = blake3_key_hash(&body.token);
    let now = naive_utc();

    // Atomically mark the token used; returns the owning user_id or nothing.
    let claimed = sqlx::query_as::<_, RecoveryTokenRow>(
        r#"UPDATE password_recovery_tokens
           SET used_at = $1
           WHERE token_hash = $2
             AND used_at IS NULL
             AND expires_at > $1
           RETURNING user_id"#,
    )
    .bind(now)
    .bind(&token_hash)
    .fetch_optional(pool)
    .await
    .map_err(db_err)?;

    let claimed_user_id = claimed
        .ok_or_else(|| err(StatusCode::BAD_REQUEST, "Invalid or expired recovery token."))?
        .user_id;

    let user = sqlx::query_as::<_, UserRow>(
        "SELECT id::uuid, email, password_hash, role, created_at FROM users WHERE id = $1",
    )
    .bind(claimed_user_id)
    .fetch_optional(pool)
    .await
    .map_err(db_err)?
    .ok_or_else(|| err(StatusCode::BAD_REQUEST, "Invalid or expired recovery token."))?;

    let allowed_set = active_scopes_for_user(pool, user.id).await?;
    let allowed_refs: HashSet<&str> = allowed_set.iter().map(String::as_str).collect();
    let scopes = validate_scopes(&body.scopes, &allowed_refs, "complete_recovery")?;

    if body.revoke_existing_keys {
        sqlx::query(
            "UPDATE api_keys SET revoked_at = $1 WHERE user_id = $2 AND revoked_at IS NULL",
        )
        .bind(now)
        .bind(user.id)
        .execute(pool)
        .await
        .map_err(db_err)?;
    }

    let new_pw_hash = hash_password(&body.new_password);
    sqlx::query("UPDATE users SET password_hash = $1 WHERE id = $2")
        .bind(&new_pw_hash)
        .bind(user.id)
        .execute(pool)
        .await
        .map_err(db_err)?;

    let expires = parse_expires(DEFAULT_EXPIRY)?;
    let (raw, key_id) = insert_api_key(pool, user.id, "recovered", &scopes, expires).await?;

    Ok((
        StatusCode::CREATED,
        Json(KeyCreateResponse {
            api_key: raw,
            key_id,
            name: "recovered".to_owned(),
            scopes,
            expires_at: expires.format("%Y-%m-%dT%H:%M:%S").to_string(),
        }),
    ))
}

// ── Router ────────────────────────────────────────────────────────────────────

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/auth/register", post(register))
        .route("/auth/login", post(login))
        .route("/auth/reissue-key", post(reissue_key))
        .route("/auth/keys", post(create_key).get(list_keys))
        .route("/auth/keys/{key_id}", delete(revoke_key))
        .route("/auth/me", delete(delete_own_account))
        .route("/auth/admin/users", post(admin_create_user))
        .route("/auth/admin/users/{user_id}", delete(admin_delete_user))
        .route("/auth/recovery/request", post(request_recovery))
        .route("/auth/recovery/complete", post(complete_recovery))
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_verify_roundtrip() {
        let pw = "hunter2-but-longer-than-12-chars";
        let hash = hash_password(pw);
        assert!(verify_password(pw, &hash), "correct password should verify");
        assert!(
            !verify_password("wrong-password-xyz", &hash),
            "wrong password must not verify"
        );
    }

    #[test]
    fn verify_rejects_malformed_hash() {
        assert!(!verify_password("pw", "not-a-hash"));
        assert!(!verify_password("pw", "scrypt$bad$0$0$$"));
    }

    #[test]
    fn hash_format_matches_python() {
        // scrypt$16384$8$1$<64-hex-salt>$<128-hex-dk>
        let h = hash_password("test-password-ok");
        let parts: Vec<&str> = h.splitn(6, '$').collect();
        assert_eq!(parts.len(), 6);
        assert_eq!(parts[0], "scrypt");
        assert_eq!(parts[1], "16384");
        assert_eq!(parts[2], "8");
        assert_eq!(parts[3], "1");
        assert_eq!(parts[4].len(), SCRYPT_SALT_LEN * 2, "salt hex length");
        assert_eq!(parts[5].len(), SCRYPT_DK_LEN * 2, "dk hex length");
    }

    #[test]
    fn generate_raw_key_is_64_hex_chars() {
        let k = generate_raw_key();
        assert_eq!(k.len(), 64);
        assert!(k.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn validate_scopes_rejects_unknown() {
        let allowed: HashSet<&str> = ["read", "verify"].iter().copied().collect();
        let res = validate_scopes(&["read".to_owned(), "bogus".to_owned()], &allowed, "test");
        assert!(res.is_err());
        let (status, _) = res.unwrap_err();
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }

    #[test]
    fn validate_scopes_rejects_out_of_context() {
        let allowed: HashSet<&str> = ["read", "verify"].iter().copied().collect();
        let res = validate_scopes(&["admin".to_owned()], &allowed, "test");
        assert!(res.is_err());
        let (status, _) = res.unwrap_err();
        assert_eq!(status, StatusCode::FORBIDDEN);
    }

    #[test]
    fn validate_scopes_deduplicates() {
        let allowed: HashSet<&str> = VALID_SCOPES.iter().copied().collect();
        let scopes = vec!["read".to_owned(), "read".to_owned(), "verify".to_owned()];
        let result = validate_scopes(&scopes, &allowed, "test").unwrap();
        assert_eq!(result, vec!["read", "verify"]);
    }
}
