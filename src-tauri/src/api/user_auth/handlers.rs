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
            expires_at: expires.format("%Y-%m-%dT%H:%M:%SZ").to_string(),
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
            expires_at: expires.format("%Y-%m-%dT%H:%M:%SZ").to_string(),
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

    // Atomic: deleting keys then the user in one transaction prevents a failure
    // between the two from orphaning the user row with all its keys gone (an
    // unrecoverable state for that account).
    let mut tx = pool.begin().await.map_err(db_err)?;
    // Last-admin guard: deleting an admin removes their keys, so the same
    // self-lockout concern as `update_user_role` / `revoke_key` applies. Block
    // if this user is the last `role='admin'` user OR deleting them would strip
    // the last effective-admin key. Runs inside the delete tx (FOR UPDATE locks
    // serialize concurrent removals).
    guard_last_admin_before_delete(&mut tx, &user.id.to_string()).await?;
    sqlx::query("DELETE FROM api_keys WHERE user_id = $1::text")
        .bind(user.id)
        .execute(&mut *tx)
        .await
        .map_err(db_err)?;
    sqlx::query("DELETE FROM users WHERE id = $1::text")
        .bind(user.id)
        .execute(&mut *tx)
        .await
        .map_err(db_err)?;
    tx.commit().await.map_err(db_err)?;

    Ok(StatusCode::NO_CONTENT)
}

/// Last-admin lockout guard shared by the two account-delete paths
/// (`delete_own_account`, `admin_delete_user`). Deleting an admin user removes
/// all their API keys, so dropping the *sole* admin would strip every DB-backed
/// admin path to `/admin/*`. Mirroring `admin_users::update_user_role`, this
/// runs inside the caller's delete transaction and:
///
/// 1. Locks the `role='admin'` user set and the effective-admin-key set
///    `FOR UPDATE` so two concurrent deletions can't each see the other as
///    "another admin remains" under READ COMMITTED and both commit to zero.
/// 2. Returns `409 CONFLICT` if `target_user_id` is the last admin user, or if
///    deleting it removes the last effective-admin key.
///
/// As elsewhere, the env `OLYMPUS_ADMIN_KEY` operator path and SBT-derived
/// admin scope remain independent recovery roots — this is a deliberately
/// fail-safe subset (never blocks while another effective-admin key/user
/// exists; may conservatively block in the rare SBT-only-admin case).
async fn guard_last_admin_before_delete(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    target_user_id: &str,
) -> Result<(), ApiError> {
    // Lock the admin user set + the effective-admin-key set so the checks below
    // are serialized against concurrent demotions/revokes/deletes. The
    // effective-admin-key predicate (active key + role='admin' owner + 'admin'
    // in the JSON scopes) is spelled out inline as a `&'static str` — the repo
    // forbids dynamic SQL strings (see `admin_users.rs` for the rationale).
    sqlx::query("SELECT id FROM users WHERE role = 'admin' FOR UPDATE")
        .execute(&mut **tx)
        .await
        .map_err(db_err)?;
    sqlx::query(
        "SELECT k.id FROM api_keys k JOIN users u ON u.id = k.user_id \
         WHERE k.revoked_at IS NULL AND (k.expires_at IS NULL OR k.expires_at > NOW()) \
           AND u.role = 'admin' AND jsonb_exists(k.scopes::jsonb, 'admin') \
         FOR UPDATE OF k",
    )
    .execute(&mut **tx)
    .await
    .map_err(db_err)?;

    // Is the target an admin user with no other admin remaining?
    let last_admin_user: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM users WHERE id = $1::text AND role = 'admin') \
             AND NOT EXISTS(SELECT 1 FROM users WHERE role = 'admin' AND id <> $1::text)",
    )
    .bind(target_user_id)
    .fetch_one(&mut **tx)
    .await
    .map_err(db_err)?;
    if last_admin_user {
        return Err(err(
            StatusCode::CONFLICT,
            "cannot delete the last remaining admin (UI recovery would require OLYMPUS_ADMIN_KEY)",
        ));
    }

    // Would deleting this user's keys strip the last effective-admin key?
    let removes_last_admin_key: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM api_keys k JOIN users u ON u.id = k.user_id \
                       WHERE k.revoked_at IS NULL AND (k.expires_at IS NULL OR k.expires_at > NOW()) \
                         AND u.role = 'admin' AND jsonb_exists(k.scopes::jsonb, 'admin') \
                         AND k.user_id = $1::text) \
             AND NOT EXISTS(SELECT 1 FROM api_keys k JOIN users u ON u.id = k.user_id \
                            WHERE k.revoked_at IS NULL AND (k.expires_at IS NULL OR k.expires_at > NOW()) \
                              AND u.role = 'admin' AND jsonb_exists(k.scopes::jsonb, 'admin') \
                              AND k.user_id <> $1::text)",
    )
    .bind(target_user_id)
    .fetch_one(&mut **tx)
    .await
    .map_err(db_err)?;
    if removes_last_admin_key {
        return Err(err(
            StatusCode::CONFLICT,
            "cannot delete the last admin-scoped key (UI recovery would require OLYMPUS_ADMIN_KEY)",
        ));
    }
    Ok(())
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

    // Atomic delete (see `delete_own_account`): keys + user row in one tx so a
    // mid-sequence failure can't leave a keyless orphan user.
    let mut tx = pool.begin().await.map_err(db_err)?;
    // Last-admin guard (see `guard_last_admin_before_delete`): refuse to delete
    // the sole admin user or strip the last effective-admin key.
    guard_last_admin_before_delete(&mut tx, &user_id.to_string()).await?;
    sqlx::query("DELETE FROM api_keys WHERE user_id = $1::text")
        .bind(user_id)
        .execute(&mut *tx)
        .await
        .map_err(db_err)?;
    sqlx::query("DELETE FROM users WHERE id = $1::text")
        .bind(user_id)
        .execute(&mut *tx)
        .await
        .map_err(db_err)?;
    tx.commit().await.map_err(db_err)?;

    Ok(StatusCode::NO_CONTENT)
}
