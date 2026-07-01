//! User-facing signing-key operations: register, list, revoke, and the
//! feature-gated dev-generate bootstrap helper.

use axum::{
    extract::{Path, State},
    http::StatusCode,
    Json,
};
use serde::Deserialize;
use uuid::Uuid;

use crate::api::middleware::auth::{AuthenticatedKey, RateLimit};
use crate::state::AppState;

use super::common::{
    db_err, err, err_code, signing_key_response, utc_now, validate_signing_key_label_purpose,
    verify_signing_key_possession, ApiError, SigningKeyRegisterRequest, SigningKeyResponse,
    SigningKeyRow,
};
#[cfg(feature = "dev-signing-route")]
use super::common::{SigningKeyDevGenerateRequest, SigningKeyDevGenerateResponse};

// ── Route: POST /key/signing ──────────────────────────────────────────────────

/// Register an Ed25519 public signing key to the authenticated DB account.
///
/// Requires `proof_signature` — an Ed25519 signature of
/// `signing_key_binding_payload(public_key, label, purpose)` — to prove the
/// caller controls the corresponding private key.
///
/// Idempotent: re-registering the same key for the same account returns the
/// existing row.  Registering a key that already belongs to a different account
/// returns 409.
pub(super) async fn register_signing_key(
    State(state): State<AppState>,
    auth: AuthenticatedKey,
    _rl: RateLimit,
    Json(body): Json<SigningKeyRegisterRequest>,
) -> Result<(StatusCode, Json<SigningKeyResponse>), ApiError> {
    // Audit M-2: registering a signing key is a write to the caller's own
    // account-key state. Gate it like every other mutating endpoint instead
    // of accepting any authenticated key regardless of scope. (Operations
    // remain confined to the caller's own user via `user_id` predicates.)
    if !auth.has_scope("write") && !auth.has_scope("admin") {
        return Err(err(
            StatusCode::FORBIDDEN,
            "API key lacks required scope: 'write'.",
        ));
    }
    // Validate public_key format first.
    let pk_bytes = hex::decode(&body.public_key).map_err(|_| {
        err_code(
            StatusCode::UNPROCESSABLE_ENTITY,
            "public_key must be hex-encoded.",
            "INVALID_PUBLIC_KEY",
        )
    })?;
    if pk_bytes.len() != 32 {
        return Err(err_code(
            StatusCode::UNPROCESSABLE_ENTITY,
            "public_key must be a 32-byte Ed25519 public key.",
            "INVALID_PUBLIC_KEY",
        ));
    }
    let public_key_hex = body.public_key.to_lowercase();

    let label = validate_signing_key_label_purpose(&body.label, &body.purpose)?;

    // Verify Ed25519 possession proof.
    verify_signing_key_possession(
        &public_key_hex,
        &label,
        &body.purpose,
        body.proof_signature.as_deref(),
    )?;

    let pool = state
        .pool
        .as_ref()
        .ok_or_else(|| err(StatusCode::SERVICE_UNAVAILABLE, "Database unavailable."))?;

    // Idempotency check — return existing active row for the same public key.
    let existing = sqlx::query_as::<_, SigningKeyRow>(
        "SELECT key_id, user_id, public_key, label, purpose,
                created_at, revoked_at, replaced_by_key_id
         FROM account_signing_keys
         WHERE public_key = $1",
    )
    .bind(&public_key_hex)
    .fetch_optional(pool)
    .await
    .map_err(db_err)?;

    if let Some(row) = existing {
        // `row.user_id` decodes from the `VARCHAR(36)` column as `String`;
        // compare against the hyphenated-hex form of the caller's `Uuid`.
        if row.user_id != auth.user_id.to_string() {
            return Err(err(StatusCode::CONFLICT, "Signing key already registered."));
        }
        if row.revoked_at.is_some() {
            return Err(err(StatusCode::CONFLICT, "Signing key has been revoked."));
        }
        return Ok((StatusCode::OK, Json(signing_key_response(&row))));
    }

    let key_id = Uuid::new_v4();
    let now = utc_now();

    // The `key_id` / `user_id` columns are `VARCHAR(36)`; bind the hyphenated
    // string form, not the `Uuid` (sqlx 0.9 would otherwise encode a postgres
    // `uuid` and the type mismatch 500s the INSERT).
    sqlx::query(
        "INSERT INTO account_signing_keys
             (key_id, user_id, public_key, label, purpose, created_at)
         VALUES ($1, $2, $3, $4, $5, $6)",
    )
    .bind(key_id.to_string())
    .bind(auth.user_id.to_string())
    .bind(&public_key_hex)
    .bind(&label)
    .bind(&body.purpose)
    .bind(now)
    .execute(pool)
    .await
    .map_err(db_err)?;

    let row = SigningKeyRow {
        key_id: key_id.to_string(),
        user_id: auth.user_id.to_string(),
        public_key: public_key_hex,
        label,
        purpose: body.purpose,
        created_at: now,
        revoked_at: None,
        replaced_by_key_id: None,
    };
    Ok((StatusCode::CREATED, Json(signing_key_response(&row))))
}

// ── Route: GET /key/signing ───────────────────────────────────────────────────

/// List all signing keys registered to the authenticated account.
pub(super) async fn list_signing_keys(
    State(state): State<AppState>,
    auth: AuthenticatedKey,
    _rl: RateLimit,
) -> Result<Json<Vec<SigningKeyResponse>>, ApiError> {
    // Audit M-2: require a read capability, consistent with the rest of the
    // API. Scoped to the caller's own keys via `WHERE user_id = $1`.
    if !auth.has_scope("read") && !auth.has_scope("admin") {
        return Err(err(
            StatusCode::FORBIDDEN,
            "API key lacks required scope: 'read'.",
        ));
    }
    let pool = state
        .pool
        .as_ref()
        .ok_or_else(|| err(StatusCode::SERVICE_UNAVAILABLE, "Database unavailable."))?;

    let rows = sqlx::query_as::<_, SigningKeyRow>(
        "SELECT key_id, user_id, public_key, label, purpose,
                created_at, revoked_at, replaced_by_key_id
         FROM account_signing_keys
         WHERE user_id = $1
         ORDER BY created_at",
    )
    .bind(auth.user_id.to_string())
    .fetch_all(pool)
    .await
    .map_err(db_err)?;

    Ok(Json(rows.iter().map(signing_key_response).collect()))
}

// ── Route: DELETE /key/signing/{key_id} ──────────────────────────────────────

/// Revoke a signing key.  Accepts an optional `replaced_by_key_id` query param
/// to record the superseding key (matches the Python `replaced_by_key_id`
/// query parameter).
pub(super) async fn revoke_signing_key(
    State(state): State<AppState>,
    auth: AuthenticatedKey,
    _rl: RateLimit,
    Path(key_id): Path<Uuid>,
    axum::extract::Query(params): axum::extract::Query<RevokeSigningKeyParams>,
) -> Result<Json<SigningKeyResponse>, ApiError> {
    // Audit M-2: revoking a signing key mutates account-key state — gate on
    // `write` like registration. Scoped to the caller's own keys below.
    if !auth.has_scope("write") && !auth.has_scope("admin") {
        return Err(err(
            StatusCode::FORBIDDEN,
            "API key lacks required scope: 'write'.",
        ));
    }
    let pool = state
        .pool
        .as_ref()
        .ok_or_else(|| err(StatusCode::SERVICE_UNAVAILABLE, "Database unavailable."))?;

    let row = sqlx::query_as::<_, SigningKeyRow>(
        "SELECT key_id, user_id, public_key, label, purpose,
                created_at, revoked_at, replaced_by_key_id
         FROM account_signing_keys
         WHERE key_id = $1 AND user_id = $2",
    )
    .bind(key_id.to_string())
    .bind(auth.user_id.to_string())
    .fetch_optional(pool)
    .await
    .map_err(db_err)?
    .ok_or_else(|| err(StatusCode::NOT_FOUND, "Signing key not found."))?;

    if row.revoked_at.is_some() {
        return Err(err(StatusCode::CONFLICT, "Signing key already revoked."));
    }

    // Validate replacement key exists and belongs to the same user.
    if let Some(replacement_id) = params.replaced_by_key_id {
        let exists = sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM account_signing_keys
             WHERE key_id = $1 AND user_id = $2 AND revoked_at IS NULL",
        )
        .bind(replacement_id.to_string())
        .bind(auth.user_id.to_string())
        .fetch_one(pool)
        .await
        .map_err(db_err)?;
        if exists == 0 {
            return Err(err(
                StatusCode::NOT_FOUND,
                "Replacement signing key not found.",
            ));
        }
    }

    let now = utc_now();
    // `replaced_by_key_id` / `revoked_by_key_id` / `key_id` are all
    // `VARCHAR(36)`; bind the string forms of the `Uuid`s. `revoked_at` is
    // `TIMESTAMPTZ`, so `now: DateTime<Utc>` encodes correctly.
    sqlx::query(
        "UPDATE account_signing_keys
         SET revoked_at = $1,
             replaced_by_key_id = $2,
             revoked_by_key_id = $3
         WHERE key_id = $4",
    )
    .bind(now)
    .bind(params.replaced_by_key_id.map(|u| u.to_string()))
    .bind(auth.db_id.to_string()) // the api_keys.id that performed the revocation
    .bind(key_id.to_string())
    .execute(pool)
    .await
    .map_err(db_err)?;

    let updated = SigningKeyRow {
        revoked_at: Some(now),
        replaced_by_key_id: params.replaced_by_key_id.map(|u| u.to_string()),
        ..row
    };
    Ok(Json(signing_key_response(&updated)))
}

#[derive(Deserialize)]
pub struct RevokeSigningKeyParams {
    pub replaced_by_key_id: Option<Uuid>,
}

// ── Route: POST /key/signing/dev-generate ─────────────────────────────────────

/// Dev-only first-boot helper: generate an Ed25519 keypair, register the
/// public key, and return the **private key once only**.
///
/// Gated behind the opt-in `dev-signing-route` Cargo feature (OFF by default),
/// so production — and ordinary `cargo tauri dev` — builds physically lack this
/// route. When the feature is enabled it is additionally gated at runtime:
/// active only when `OLYMPUS_ENV=development` AND
/// `OLYMPUS_ALLOW_DEV_SIGNING_KEY_BOOTSTRAP=1`. Applies the same label/purpose
/// validation as `POST /key/signing`.
#[cfg(feature = "dev-signing-route")]
pub(super) async fn dev_generate_signing_key(
    State(state): State<AppState>,
    auth: AuthenticatedKey,
    _rl: RateLimit,
    Json(body): Json<SigningKeyDevGenerateRequest>,
) -> Result<(StatusCode, Json<SigningKeyDevGenerateResponse>), ApiError> {
    let dev_mode = crate::env::is_development();
    let bootstrap_allowed = std::env::var("OLYMPUS_ALLOW_DEV_SIGNING_KEY_BOOTSTRAP")
        .ok()
        .as_deref()
        == Some("1");
    if !dev_mode || !bootstrap_allowed {
        return Err(err(StatusCode::NOT_FOUND, "Not found."));
    }

    let pool = state
        .pool
        .as_ref()
        .ok_or_else(|| err(StatusCode::SERVICE_UNAVAILABLE, "Database unavailable."))?;

    // Generate Ed25519 keypair.
    let signing_key = ed25519_dalek::SigningKey::generate(&mut rand::thread_rng());
    let public_key_hex = hex::encode(signing_key.verifying_key().to_bytes());
    let private_key_hex = hex::encode(signing_key.to_bytes());

    // Same label + purpose validation as the public registration path, so the
    // dev route can't persist rows that violate the normal constraints.
    let label = validate_signing_key_label_purpose(&body.label, &body.purpose)?;
    let key_id = Uuid::new_v4();
    let now = utc_now();

    // `VARCHAR(36)` columns take the string forms; `created_at` is `TIMESTAMPTZ`.
    sqlx::query(
        "INSERT INTO account_signing_keys
             (key_id, user_id, public_key, label, purpose, created_at)
         VALUES ($1, $2, $3, $4, $5, $6)",
    )
    .bind(key_id.to_string())
    .bind(auth.user_id.to_string())
    .bind(&public_key_hex)
    .bind(&label)
    .bind(&body.purpose)
    .bind(now)
    .execute(pool)
    .await
    .map_err(db_err)?;

    tracing::warn!(
        "Dev-generated signing key {} for user={}; private key returned once only",
        key_id,
        auth.user_id,
    );

    Ok((
        StatusCode::CREATED,
        Json(SigningKeyDevGenerateResponse {
            key_id: key_id.to_string(),
            user_id: auth.user_id.to_string(),
            public_key: public_key_hex,
            label,
            purpose: body.purpose,
            created_at: now.format("%Y-%m-%dT%H:%M:%S").to_string(),
            revoked_at: None,
            replaced_by_key_id: None,
            private_key: private_key_hex,
        }),
    ))
}
