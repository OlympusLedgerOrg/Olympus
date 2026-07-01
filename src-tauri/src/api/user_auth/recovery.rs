//! Password-recovery route handlers: token issue + token consumption.

use std::collections::HashSet;

use axum::{extract::State, http::StatusCode, Json};
use uuid::Uuid;

use crate::api::middleware::auth::{blake3_key_hash, RegistrationRateLimit};
use crate::state::AppState;

use super::crypto::{check_password_len, hash_password};
use super::helpers::{
    active_scopes_for_user, db_err, err, insert_api_key, naive_utc, normalize_email,
    validate_scopes, ApiError,
};
use super::types::{
    default_expiry, parse_expires, KeyCreateResponse, RecoveryCompleteRequest, RecoveryRequest,
    RecoveryRequestResponse, RecoveryTokenRow, UserRow,
};

/// POST /auth/recovery/request — issue a single-use password-recovery token.
///
/// Never reveals whether the email exists (identical response either way).
/// Returns the raw token in the response body only when
/// `OLYMPUS_ENV=development` AND `OLYMPUS_RETURN_RECOVERY_TOKEN=1`.
pub(super) async fn request_recovery(
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
    .bind(normalize_email(&body.email))
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

    let return_token = crate::env::is_development()
        && std::env::var("OLYMPUS_RETURN_RECOVERY_TOKEN")
            .ok()
            .as_deref()
            == Some("1");

    let response = RecoveryRequestResponse {
        detail: MSG.to_owned(),
        recovery_token: return_token.then_some(raw_token),
        expires_at: return_token.then(|| expires_at.format("%Y-%m-%dT%H:%M:%SZ").to_string()),
    };
    Ok((StatusCode::ACCEPTED, Json(response)))
}

/// POST /auth/recovery/complete — consume token, reset password, issue key.
///
/// Uses an atomic `UPDATE … RETURNING` to claim the token, preventing race
/// conditions when two concurrent requests arrive with the same token.
pub(super) async fn complete_recovery(
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
            expires_at: expires.format("%Y-%m-%dT%H:%M:%SZ").to_string(),
        }),
    ))
}
