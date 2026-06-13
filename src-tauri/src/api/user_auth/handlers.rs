//! Axum route handlers for registration, login, key lifecycle, account
//! deletion, and the admin user-management endpoints.

use std::collections::HashSet;

use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    Json,
};
use uuid::Uuid;

use crate::api::middleware::auth::{
    require_admin_auth, AuthenticatedKey, RateLimit, RegistrationRateLimit,
};
use crate::state::AppState;

use super::crypto::{dummy_hash_ref, verify_password};
use super::helpers::naive_utc;
use super::helpers::{
    active_scopes_for_user, create_user_with_key, db_err, err, insert_api_key, key_info,
    normalize_email, public_write_registration_enabled, registration_approval_valid,
    validate_scopes, ApiError, ALLOW_PUBLIC_WRITE_REG_ENV, PRIVILEGED_SCOPES,
    REGISTER_BOOTSTRAP_LOCK, REGISTRATION_APPROVAL_HEADER, SELF_SERVICE_SCOPES, VALID_SCOPES,
};
use super::types::{
    default_expiry, parse_expires, AdminRegisterRequest, AdminRegisterResponse, ApiKeyRow,
    DeleteAccountRequest, KeyCreateRequest, KeyCreateResponse, KeyInfo, LoginRequest,
    LoginResponse, RegisterRequest, RegisterResponse, ReissueKeyRequest, UserRow,
};

// ── Route handlers ────────────────────────────────────────────────────────────

/// POST /auth/register — create account + first API key.
pub(super) async fn register(
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
    // gets the `admin` role + all requested scopes, so a single-operator desktop
    // is usable immediately on first boot.
    //
    // Red-team note (reviewed, accepted as by-design): because the API is
    // loopback-only this is a *local-process* trust boundary — a hostile local
    // process that beats the operator to the first `/auth/register` would obtain
    // admin. The concurrent race is closed by the advisory lock below (two first
    // registrations cannot both win). Operators who want to remove the auto-grant
    // window can set `OLYMPUS_ADMIN_KEY` and create accounts via the admin-gated
    // `POST /auth/admin/users` (bootstrap also surfaces an admin-scoped
    // `system-bootstrap` API key once via the initial-secrets dialog). See
    // SECURITY.md → "API Authentication & Authorization Model".
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
            email: normalize_email(&body.email),
            api_key: raw_key,
            key_id,
            scopes,
        }),
    ))
}

/// POST /auth/admin/users — admin-protected user creation with chosen scopes.
pub(super) async fn admin_create_user(
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
            email: normalize_email(&body.email),
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
pub(super) async fn login(
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
    .bind(normalize_email(&body.email))
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
pub(super) async fn reissue_key(
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
    .bind(normalize_email(&body.email))
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
pub(super) async fn create_key(
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
pub(super) async fn list_keys(
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
pub(super) async fn revoke_key(
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
pub(super) async fn delete_own_account(
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
    .bind(normalize_email(&body.email))
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
pub(super) async fn admin_delete_user(
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
