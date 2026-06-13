//! Shared constants, error helpers, scope-policy validation, email
//! normalisation, registration-approval HMAC, and DB write helpers for the
//! user-auth module.
//!
//! Security note: the scope constants and `validate_scopes` /
//! `active_scopes_for_user` below are security policy (fail-closed scope
//! validation) — kept together here, semantics unchanged from the original
//! single-file module.

use std::collections::HashSet;

use axum::{http::StatusCode, Json};
use chrono::NaiveDateTime;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use sqlx::PgPool;
use subtle::ConstantTimeEq;
use uuid::Uuid;

use crate::api::middleware::auth::blake3_key_hash;

use super::crypto::{check_password_len, generate_raw_key, hash_password};
use super::types::{ApiKeyRow, KeyInfo, RegisterRequest};

// ── Constants ─────────────────────────────────────────────────────────────────
pub(super) const REGISTER_DEFAULT_SCOPES: &[&str] = &["read", "verify"];
pub(super) const KEY_DEFAULT_SCOPES: &[&str] = &["ingest", "verify"];

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
pub(super) const DEFAULT_EXPIRY_DAYS: i64 = 90;

pub(super) const VALID_SCOPES: &[&str] = &["read", "write", "ingest", "commit", "verify", "admin"];
pub(super) const SELF_SERVICE_SCOPES: &[&str] = &["read", "verify"];
pub(super) const PRIVILEGED_SCOPES: &[&str] = &["ingest", "commit", "write", "admin"];

/// Stable advisory-lock key that serializes the first-user / bootstrap-admin
/// decision in `register`. Holding it across the user-count read and the row
/// insert prevents the TOCTOU where two concurrent first registrations both
/// observe an empty `users` table and both receive the admin role + privileged
/// scopes (audit).
pub(super) const REGISTER_BOOTSTRAP_LOCK: i64 = 0x4F4C_5950_5245_4701;

pub(super) const ALLOW_PUBLIC_WRITE_REG_ENV: &str = "OLYMPUS_ALLOW_PUBLIC_WRITE_REGISTRATION";
pub(super) const REGISTRATION_APPROVAL_HEADER: &str = "x-admin-registration-approval";

// ── Error helper ──────────────────────────────────────────────────────────────

pub(super) type ApiError = (StatusCode, Json<serde_json::Value>);

pub(super) fn err(status: StatusCode, detail: &str) -> ApiError {
    (status, Json(serde_json::json!({"detail": detail})))
}

#[allow(dead_code)]
pub(super) fn err_code(status: StatusCode, detail: &str, code: &str) -> ApiError {
    (
        status,
        Json(serde_json::json!({"detail": detail, "code": code})),
    )
}

pub(super) fn db_err(e: sqlx::Error) -> ApiError {
    tracing::error!("database error: {e}");
    err(StatusCode::INTERNAL_SERVER_ERROR, "Database error.")
}

pub(super) fn naive_utc() -> NaiveDateTime {
    chrono::Utc::now().naive_utc()
}

// ── Scope helpers ─────────────────────────────────────────────────────────────

/// Validate and de-duplicate `requested` scopes against `allowed`.
/// Returns 400 for unknown scopes, 403 for out-of-context scopes.
pub(super) fn validate_scopes(
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
pub(super) async fn active_scopes_for_user(
    pool: &PgPool,
    user_id: Uuid,
) -> Result<HashSet<String>, ApiError> {
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

// ── Email normalisation ──────────────────────────────────────────────────────

/// Canonical form for storing and looking up account emails. Email addresses
/// are treated case-insensitively in practice, so we normalise to trimmed
/// lowercase at every boundary (registration, admin create, login, reissue,
/// self-delete, recovery). This keeps storage and lookups consistent and pairs
/// with the case-insensitive UNIQUE index in migration `0046`, closing the
/// split-brain where `Alice@x.com` and `alice@x.com` were distinct accounts.
/// (Audit: email case uniqueness.)
pub(super) fn normalize_email(email: &str) -> String {
    email.trim().to_lowercase()
}

// ── Registration-approval signature (HMAC-SHA256) ─────────────────────────────

pub(super) fn registration_approval_payload(
    email: &str,
    scopes: &[String],
    expires_at: &str,
) -> String {
    let mut sorted = scopes.to_vec();
    sorted.sort();
    sorted.dedup();
    format!(
        "{}|{}|{}",
        normalize_email(email),
        sorted.join(","),
        expires_at
    )
}

pub(super) fn registration_approval_valid(
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
    let mut mac =
        Hmac::<Sha256>::new_from_slice(admin_key.as_bytes()).expect("HMAC accepts any key length");
    mac.update(payload.as_bytes());
    let expected = hex::encode(mac.finalize().into_bytes());
    bool::from(provided.as_bytes().ct_eq(expected.as_bytes()))
}

pub(super) fn public_write_registration_enabled() -> bool {
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
pub(super) async fn create_user_with_key(
    conn: &mut sqlx::PgConnection,
    email: &str,
    password: &str,
    name: &str,
    scopes: &[String],
    expires_at: NaiveDateTime,
    role: &str,
) -> Result<(Uuid, Uuid, String), ApiError> {
    // Normalise before the duplicate check and insert so case/whitespace
    // variants collapse to one account (matches the case-insensitive UNIQUE
    // index in migration 0046). (Audit: email case uniqueness.)
    let email = normalize_email(email);
    // Check for duplicate email.
    let existing = sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM users WHERE email = $1")
        .bind(&email)
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
pub(super) async fn insert_api_key<'e, E>(
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

pub(super) fn key_info(row: &ApiKeyRow) -> Result<KeyInfo, ApiError> {
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
