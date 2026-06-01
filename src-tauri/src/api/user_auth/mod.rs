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
use chrono::{DateTime, NaiveDateTime, Utc};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use sqlx::PgPool;
use subtle::ConstantTimeEq;
use uuid::Uuid;

use crate::api::middleware::auth::{
    blake3_key_hash, require_admin_auth, AuthenticatedKey, RateLimit, RegistrationRateLimit,
};
use crate::state::AppState;

mod crypto;
use crypto::{
    check_password_len, dummy_hash_ref, generate_raw_key, hash_password, verify_password,
};

// ── Constants ─────────────────────────────────────────────────────────────────
const REGISTER_DEFAULT_SCOPES: &[&str] = &["read", "verify"];
const KEY_DEFAULT_SCOPES: &[&str] = &["ingest", "verify"];

/// Audit L-7: API keys used to default to `expires_at = "2099-01-01T00:00:00Z"`
/// — effectively non-expiring credentials. That's appropriate as an explicit
/// opt-in for desktop-bootstrap keys, but it's the wrong default for normal
/// issued keys: a forgotten key in a shell history or backup file stays
/// valid forever.
///
/// New default: 90 days from issue time. Aligns with standard rotation
/// horizons (AWS / GCP / GitHub's own service-token recommendations) and
/// makes "renew" a deliberate operational action via `POST /auth/reissue-key`
/// rather than something users never think about.
///
/// Long-lived keys remain available: clients that explicitly want a
/// far-future expiry can still POST `expires_at: "2099-01-01T00:00:00Z"`
/// — the validation path at `parse_expires` accepts any well-formed
/// ISO-8601 datetime in the future.
const DEFAULT_EXPIRY_DAYS: i64 = 90;

const VALID_SCOPES: &[&str] = &["read", "write", "ingest", "commit", "verify", "admin"];
const SELF_SERVICE_SCOPES: &[&str] = &["read", "verify"];
const PRIVILEGED_SCOPES: &[&str] = &["ingest", "commit", "write", "admin"];

/// Stable advisory-lock key that serializes the first-user / bootstrap-admin
/// decision in `register`. Holding it across the user-count read and the row
/// insert prevents the TOCTOU where two concurrent first registrations both
/// observe an empty `users` table and both receive the admin role + privileged
/// scopes (audit).
const REGISTER_BOOTSTRAP_LOCK: i64 = 0x4F4C_5950_5245_4701;

const ALLOW_PUBLIC_WRITE_REG_ENV: &str = "OLYMPUS_ALLOW_PUBLIC_WRITE_REGISTRATION";
const REGISTRATION_APPROVAL_HEADER: &str = "x-admin-registration-approval";

// ── Error helper ──────────────────────────────────────────────────────────────

type ApiError = (StatusCode, Json<serde_json::Value>);

fn err(status: StatusCode, detail: &str) -> ApiError {
    (status, Json(serde_json::json!({"detail": detail})))
}

fn err_code(status: StatusCode, detail: &str, code: &str) -> ApiError {
    (
        status,
        Json(serde_json::json!({"detail": detail, "code": code})),
    )
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
    // `users.created_at` is TIMESTAMPTZ (migration 0010); sqlx 0.9 refuses
    // to decode TIMESTAMPTZ into `NaiveDateTime` and the whole query 500s
    // (same mismatch documented in `admin_users.rs::UserKeyRow`). Decode as
    // `DateTime<Utc>`.
    #[allow(dead_code)]
    created_at: DateTime<Utc>,
}

#[derive(sqlx::FromRow)]
struct ApiKeyRow {
    // `api_keys.id` / `user_id` are VARCHAR(36) (migration 0010), so every
    // SELECT below casts them `id::uuid, user_id::uuid` to decode into
    // `Uuid` — and every WHERE that compares them to a bound `Uuid` casts
    // the placeholder `$n::text`. `expires_at` / `created_at` / `revoked_at`
    // are TIMESTAMPTZ, which sqlx 0.9 will only decode into `DateTime<Utc>`
    // (decoding into `NaiveDateTime` 500s — same mismatch documented in
    // `admin_users.rs::UserKeyRow`).
    id: Uuid,
    #[allow(dead_code)]
    user_id: Uuid,
    name: String,
    scopes: String,
    expires_at: DateTime<Utc>,
    created_at: DateTime<Utc>,
    revoked_at: Option<DateTime<Utc>>,
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
    REGISTER_DEFAULT_SCOPES
        .iter()
        .map(|s| s.to_string())
        .collect()
}
fn key_default_scopes() -> Vec<String> {
    KEY_DEFAULT_SCOPES.iter().map(|s| s.to_string()).collect()
}
fn default_expiry() -> String {
    let now = chrono::Utc::now();
    let exp = now + chrono::Duration::days(DEFAULT_EXPIRY_DAYS);
    exp.format("%Y-%m-%dT%H:%M:%SZ").to_string()
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
fn parse_expires(s: &str) -> Result<NaiveDateTime, ApiError> {
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
            &format!("Unknown scope(s) in {context}: {}", unknown.join(", ")),
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
async fn active_scopes_for_user(pool: &PgPool, user_id: Uuid) -> Result<HashSet<String>, ApiError> {
    let now = naive_utc();
    let rows = sqlx::query_as::<_, ApiKeyRow>(
        "SELECT id::uuid, user_id::uuid, name, scopes, expires_at, created_at, revoked_at
         FROM api_keys
         WHERE user_id = $1::text AND revoked_at IS NULL AND expires_at > $2",
    )
    .bind(user_id)
    .bind(now)
    .fetch_all(pool)
    .await
    .map_err(db_err)?;

    let mut out: HashSet<String> = REGISTER_DEFAULT_SCOPES
        .iter()
        .map(|s| s.to_string())
        .collect();
    for row in rows {
        let scopes: Vec<String> = serde_json::from_str(&row.scopes).map_err(|_| {
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
//
// The dual-path admin gate lives in `crate::api::middleware::auth::
// require_admin_auth` — the single source of truth shared with `api::admin`,
// `api::admin_users`, and `api::shards`. The admin endpoints in this module
// (`admin_create_user`, `admin_delete_user`) call it directly so their policy
// can never drift from the rest of the admin surface.

// ── Registration-approval signature (HMAC-SHA256) ─────────────────────────────

fn registration_approval_payload(email: &str, scopes: &[String], expires_at: &str) -> String {
    let mut sorted = scopes.to_vec();
    sorted.sort();
    sorted.dedup();
    format!(
        "{}|{}|{}",
        email.to_lowercase().trim(),
        sorted.join(","),
        expires_at
    )
}

fn registration_approval_valid(req: &RegisterRequest, headers: &axum::http::HeaderMap) -> bool {
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
    let mut mac =
        Hmac::<Sha256>::new_from_slice(admin_key.as_bytes()).expect("HMAC accepts any key length");
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

/// Create a user row + first API key. Operates on a caller-supplied
/// connection so the duplicate-email check and the inserts run inside the
/// caller's transaction (see `register`, which additionally holds an advisory
/// lock to make the bootstrap-admin decision atomic).
/// Returns `(user_id, key_id, raw_key)`.
async fn create_user_with_key(
    conn: &mut sqlx::PgConnection,
    email: &str,
    password: &str,
    name: &str,
    scopes: &[String],
    expires_at: NaiveDateTime,
    role: &str,
) -> Result<(Uuid, Uuid, String), ApiError> {
    // Check for duplicate email.
    let existing = sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM users WHERE email = $1")
        .bind(email)
        .fetch_one(&mut *conn)
        .await
        .map_err(db_err)?;
    if existing > 0 {
        return Err(err(StatusCode::CONFLICT, "Email already registered."));
    }
    check_password_len(password)?;

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
    .execute(&mut *conn)
    .await
    .map_err(db_err)?;

    let (raw_key, key_id) = insert_api_key(&mut *conn, user_id, name, scopes, expires_at).await?;
    Ok((user_id, key_id, raw_key))
}

/// Insert a new `api_keys` row and return `(raw_key, key_id)`.
///
/// Generic over the executor so it works against both a pooled connection
/// (`&PgPool`) for the standalone key-issue paths and a transaction
/// connection (`&mut PgConnection`) inside `create_user_with_key`.
async fn insert_api_key<'e, E>(
    executor: E,
    user_id: Uuid,
    name: &str,
    scopes: &[String],
    expires_at: NaiveDateTime,
) -> Result<(String, Uuid), ApiError>
where
    E: sqlx::Executor<'e, Database = sqlx::Postgres>,
{
    let raw = generate_raw_key();
    let key_hash = blake3_key_hash(&raw);
    let key_id = Uuid::new_v4();
    let now = naive_utc();
    let scopes_json = serde_json::to_string(scopes).expect("Vec<String> always serialises");

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
    .execute(executor)
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
    let requesting_privileged = body
        .scopes
        .iter()
        .any(|s| privileged_set.contains(s.as_str()));
    let has_admin_approval = registration_approval_valid(&body, &headers);

    // Desktop-mode auto-grant: the first registered user (no users in DB yet)
    // gets all requested scopes, including privileged ones.  This makes first-boot
    // seamless on a single-operator desktop install.
    let pool = state
        .pool
        .as_ref()
        .ok_or_else(|| err(StatusCode::SERVICE_UNAVAILABLE, "Database unavailable."))?;

    // Hold a transaction-scoped advisory lock across the user-count read and
    // the row insert so the first-user / bootstrap-admin decision is atomic.
    // Without it, two concurrent first registrations could both see an empty
    // table and both be granted the admin role + privileged scopes (audit).
    let mut tx = pool.begin().await.map_err(db_err)?;
    sqlx::query("SELECT pg_advisory_xact_lock($1)")
        .bind(REGISTER_BOOTSTRAP_LOCK)
        .execute(&mut *tx)
        .await
        .map_err(db_err)?;

    let user_count: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM users WHERE role != 'system'")
        .fetch_one(&mut *tx)
        .await
        .map_err(db_err)?;
    let is_first_user = user_count.0 == 0;

    if requesting_privileged
        && !is_first_user
        && !public_write_registration_enabled()
        && !has_admin_approval
    {
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
    let (user_id, key_id, raw_key) = create_user_with_key(
        &mut tx,
        &body.email,
        &body.password,
        &body.name,
        &scopes,
        expires,
        role,
    )
    .await?;
    tx.commit().await.map_err(db_err)?;

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
    let pool = state
        .pool
        .as_ref()
        .ok_or_else(|| err(StatusCode::SERVICE_UNAVAILABLE, "Database unavailable."))?;
    require_admin_auth(&headers, pool, &state.bjj_trusted_issuers).await?;

    if body.role != "user" && body.role != "admin" {
        return Err(err(
            StatusCode::UNPROCESSABLE_ENTITY,
            "role must be 'user' or 'admin'.",
        ));
    }
    let allowed: HashSet<&str> = VALID_SCOPES.iter().copied().collect();
    let scopes = validate_scopes(&body.scopes, &allowed, "admin_create_user")?;
    let expires = parse_expires(&body.expires_at)?;

    let mut tx = pool.begin().await.map_err(db_err)?;
    let (user_id, key_id, raw_key) = create_user_with_key(
        &mut tx,
        &body.email,
        &body.password,
        &body.name,
        &scopes,
        expires,
        &body.role,
    )
    .await?;
    tx.commit().await.map_err(db_err)?;

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
    let pool = state
        .pool
        .as_ref()
        .ok_or_else(|| err(StatusCode::SERVICE_UNAVAILABLE, "Database unavailable."))?;

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
        .unwrap_or_else(|| dummy_hash_ref());

    if !verify_password(&body.password, stored) || user_opt.is_none() {
        return Err(err(StatusCode::UNAUTHORIZED, "Invalid email or password."));
    }
    let user = user_opt.unwrap(); // safe: checked above

    let now = naive_utc();
    let rows = sqlx::query_as::<_, ApiKeyRow>(
        "SELECT id::uuid, user_id::uuid, name, scopes, expires_at, created_at, revoked_at
         FROM api_keys
         WHERE user_id = $1::text AND revoked_at IS NULL AND expires_at > $2
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
    let pool = state
        .pool
        .as_ref()
        .ok_or_else(|| err(StatusCode::SERVICE_UNAVAILABLE, "Database unavailable."))?;

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
        .unwrap_or_else(|| dummy_hash_ref());

    if !verify_password(&body.password, stored) || user_opt.is_none() {
        return Err(err(StatusCode::UNAUTHORIZED, "Invalid email or password."));
    }
    let user = user_opt.unwrap();

    let allowed_set = active_scopes_for_user(pool, user.id).await?;
    let allowed_refs: HashSet<&str> = allowed_set.iter().map(String::as_str).collect();
    let scopes = validate_scopes(&body.scopes, &allowed_refs, "reissue_key")?;
    let expires = parse_expires(&default_expiry())?;
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
    let pool = state
        .pool
        .as_ref()
        .ok_or_else(|| err(StatusCode::SERVICE_UNAVAILABLE, "Database unavailable."))?;

    // New key scopes must be ⊆ caller's scopes — prevents privilege escalation.
    let caller_allowed: HashSet<&str> = auth.scopes.iter().map(String::as_str).collect();
    let scopes = validate_scopes(&body.scopes, &caller_allowed, "create_key")?;
    let expires = parse_expires(&body.expires_at)?;
    let (raw, key_id) = insert_api_key(pool, auth.user_id, &body.name, &scopes, expires).await?;

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
    let pool = state
        .pool
        .as_ref()
        .ok_or_else(|| err(StatusCode::SERVICE_UNAVAILABLE, "Database unavailable."))?;

    let now = naive_utc();
    let rows = sqlx::query_as::<_, ApiKeyRow>(
        "SELECT id::uuid, user_id::uuid, name, scopes, expires_at, created_at, revoked_at
         FROM api_keys
         WHERE user_id = $1::text AND revoked_at IS NULL AND expires_at > $2
         ORDER BY created_at",
    )
    .bind(auth.user_id)
    .bind(now)
    .fetch_all(pool)
    .await
    .map_err(db_err)?;

    rows.iter()
        .map(key_info)
        .collect::<Result<Vec<_>, _>>()
        .map(Json)
}

/// DELETE /auth/keys/{key_id} — revoke one of the caller's keys.
async fn revoke_key(
    State(state): State<AppState>,
    auth: AuthenticatedKey,
    _rl: RateLimit,
    Path(key_id): Path<Uuid>,
) -> Result<StatusCode, ApiError> {
    let pool = state
        .pool
        .as_ref()
        .ok_or_else(|| err(StatusCode::SERVICE_UNAVAILABLE, "Database unavailable."))?;

    let row = sqlx::query_as::<_, ApiKeyRow>(
        "SELECT id::uuid, user_id::uuid, name, scopes, expires_at, created_at, revoked_at
         FROM api_keys WHERE id = $1::text AND user_id = $2::text",
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

    sqlx::query("UPDATE api_keys SET revoked_at = $1 WHERE id = $2::text")
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
    let pool = state
        .pool
        .as_ref()
        .ok_or_else(|| err(StatusCode::SERVICE_UNAVAILABLE, "Database unavailable."))?;

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
        .unwrap_or_else(|| dummy_hash_ref());

    if !verify_password(&body.password, stored) || user_opt.is_none() {
        return Err(err(StatusCode::UNAUTHORIZED, "Invalid email or password."));
    }
    let user = user_opt.unwrap();

    sqlx::query("DELETE FROM api_keys WHERE user_id = $1::text")
        .bind(user.id)
        .execute(pool)
        .await
        .map_err(db_err)?;
    sqlx::query("DELETE FROM users WHERE id = $1::text")
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
    let pool = state
        .pool
        .as_ref()
        .ok_or_else(|| err(StatusCode::SERVICE_UNAVAILABLE, "Database unavailable."))?;
    // Dual-path admin gate — identical to the `admin_create_user` sibling and
    // the rest of the admin user-management surface (see `admin_users.rs`):
    // accept either the operator `OLYMPUS_ADMIN_KEY` OR an admin-role +
    // admin-scope API key. Previously this endpoint alone required the
    // env-only operator key, so an admin-role key holder could create users
    // but not delete them (and the route 503'd entirely when no operator key
    // was configured). Aligning the gate removes that divergent policy.
    require_admin_auth(&headers, pool, &state.bjj_trusted_issuers).await?;

    let exists = sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM users WHERE id = $1::text")
        .bind(user_id)
        .fetch_one(pool)
        .await
        .map_err(db_err)?;
    if exists == 0 {
        return Err(err(StatusCode::NOT_FOUND, "User not found."));
    }

    sqlx::query("DELETE FROM api_keys WHERE user_id = $1::text")
        .bind(user_id)
        .execute(pool)
        .await
        .map_err(db_err)?;
    sqlx::query("DELETE FROM users WHERE id = $1::text")
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

    let pool = state
        .pool
        .as_ref()
        .ok_or_else(|| err(StatusCode::SERVICE_UNAVAILABLE, "Database unavailable."))?;

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
         VALUES ($1::text, $2::text, $3, $4, $5)",
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
        && std::env::var("OLYMPUS_RETURN_RECOVERY_TOKEN")
            .ok()
            .as_deref()
            == Some("1");

    let response = RecoveryRequestResponse {
        detail: MSG.to_owned(),
        recovery_token: return_token.then_some(raw_token),
        expires_at: return_token.then(|| expires_at.format("%Y-%m-%dT%H:%M:%S").to_string()),
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
    check_password_len(&body.new_password)?;
    let pool = state
        .pool
        .as_ref()
        .ok_or_else(|| err(StatusCode::SERVICE_UNAVAILABLE, "Database unavailable."))?;

    let token_hash = blake3_key_hash(&body.token);
    let now = naive_utc();

    // Atomically mark the token used; returns the owning user_id or nothing.
    let claimed = sqlx::query_as::<_, RecoveryTokenRow>(
        r#"UPDATE password_recovery_tokens
           SET used_at = $1
           WHERE token_hash = $2
             AND used_at IS NULL
             AND expires_at > $1
           RETURNING user_id::uuid"#,
    )
    .bind(now)
    .bind(&token_hash)
    .fetch_optional(pool)
    .await
    .map_err(db_err)?;

    let claimed_user_id = claimed
        .ok_or_else(|| {
            err(
                StatusCode::BAD_REQUEST,
                "Invalid or expired recovery token.",
            )
        })?
        .user_id;

    let user = sqlx::query_as::<_, UserRow>(
        "SELECT id::uuid, email, password_hash, role, created_at FROM users WHERE id = $1::text",
    )
    .bind(claimed_user_id)
    .fetch_optional(pool)
    .await
    .map_err(db_err)?
    .ok_or_else(|| {
        err(
            StatusCode::BAD_REQUEST,
            "Invalid or expired recovery token.",
        )
    })?;

    let allowed_set = active_scopes_for_user(pool, user.id).await?;
    let allowed_refs: HashSet<&str> = allowed_set.iter().map(String::as_str).collect();
    let scopes = validate_scopes(&body.scopes, &allowed_refs, "complete_recovery")?;

    if body.revoke_existing_keys {
        sqlx::query(
            "UPDATE api_keys SET revoked_at = $1 WHERE user_id = $2::text AND revoked_at IS NULL",
        )
        .bind(now)
        .bind(user.id)
        .execute(pool)
        .await
        .map_err(db_err)?;
    }

    let new_pw_hash = hash_password(&body.new_password);
    sqlx::query("UPDATE users SET password_hash = $1 WHERE id = $2::text")
        .bind(&new_pw_hash)
        .bind(user.id)
        .execute(pool)
        .await
        .map_err(db_err)?;

    let expires = parse_expires(&default_expiry())?;
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_expiry_is_short_window_not_year_2099() {
        let exp_str = default_expiry();
        let parsed = parse_expires(&exp_str).expect("default_expiry must be well-formed");
        let now = chrono::Utc::now().naive_utc();
        let delta = parsed.signed_duration_since(now);
        let days = delta.num_days();
        assert!(
            (DEFAULT_EXPIRY_DAYS - 1..=DEFAULT_EXPIRY_DAYS + 1).contains(&days),
            "default_expiry should land within ±1 day of DEFAULT_EXPIRY_DAYS \
             ({DEFAULT_EXPIRY_DAYS}); got {days} days from now"
        );
        // Belt-and-braces: the legacy sentinel year is never the default.
        assert!(
            !exp_str.starts_with("2099"),
            "default_expiry must not regress to the legacy year-2099 sentinel"
        );
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

    #[test]
    fn registration_approval_payload_is_canonical() {
        // The HMAC payload must be stable regardless of how the caller cased
        // the email or ordered/duplicated the scopes: email lowercased+trimmed,
        // scopes sorted + deduped, pipe-joined with the expiry. A drift here
        // would silently invalidate every admin-signed approval header.
        let p = registration_approval_payload(
            "  Alice@Example.COM ",
            &["verify".to_owned(), "read".to_owned(), "verify".to_owned()],
            "2099-01-01T00:00:00Z",
        );
        assert_eq!(p, "alice@example.com|read,verify|2099-01-01T00:00:00Z");
    }
}
