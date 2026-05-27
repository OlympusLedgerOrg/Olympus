//! Admin user-management routes.
//!
//! Gated by [`require_admin_auth`] — accepts either the operator-only
//! `OLYMPUS_ADMIN_KEY` env var (sent via the `x-admin-key` header) OR a
//! regular API key whose owning user has `role = 'admin'` and whose
//! scope set contains `admin`. The dual path eliminates a second root
//! credential with divergent policy; normal API-key revocation and role
//! demotion both immediately revoke admin access. Lets the operator:
//!
//! * `GET /admin/users` — list users + their key scopes (no raw keys).
//! * `POST /admin/users/{user_id}/keys` — mint a fresh API key with
//!   chosen scopes. Raw key returned ONCE.
//! * `PATCH /admin/keys/{key_id}/scopes` — update an existing key's
//!   scope set.
//! * `DELETE /admin/keys/{key_id}` — revoke a key (DELETE row).
//! * `PATCH /admin/users/{user_id}/role` — promote/demote
//!   (`user` / `admin`).
//!
//! Together these eliminate the operator-SQL pattern: any user can be
//! brought up to admin / commit / verify scope from the desktop UI
//! without psql or shell access. The `OLYMPUS_ADMIN_KEY` gate is the
//! root of trust — see [`super::keys::require_admin_key`].

use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    routing::{delete, get, patch, post},
    Json, Router,
};
use chrono::{DateTime, NaiveDateTime, Utc};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::api::middleware::auth::{blake3_key_hash, RateLimit};
use crate::state::AppState;

/// Render a BN254 `Fr` field element as its decimal string — matches
/// the encoding used everywhere else in the workspace
/// (federation::checkpoint::fr_to_decimal, anchoring helpers, etc.)
/// so a BJJ pubkey looks identical regardless of which subsystem
/// emitted it.
fn fr_to_decimal(f: &ark_bn254::Fr) -> String {
    use ark_ff::{BigInteger, PrimeField};
    let bytes = f.into_bigint().to_bytes_be();
    num_bigint::BigUint::from_bytes_be(&bytes).to_string()
}

type ApiError = (StatusCode, Json<serde_json::Value>);

fn err(status: StatusCode, detail: &str) -> ApiError {
    (status, Json(json!({ "detail": detail })))
}

fn db_or_503(state: &AppState) -> Result<&sqlx::PgPool, ApiError> {
    state
        .pool
        .as_ref()
        .ok_or_else(|| err(StatusCode::SERVICE_UNAVAILABLE, "Database unavailable"))
}

/// Dual-path admin gate.
///
/// Accepts EITHER:
///
/// 1. The legacy operator path: `OLYMPUS_ADMIN_KEY` env var set + matching
///    `x-admin-key` header (constant-time compare). This remains for
///    bootstrap / break-glass scenarios where no DB-resident admin key
///    exists yet.
/// 2. A regular API key (via `x-api-key` or `Authorization: Bearer …`)
///    belonging to a user with `role = 'admin'` AND carrying the `admin`
///    scope — the same `is_admin_role && has_admin_scope` policy enforced
///    by `super::admin::require_admin_scoped`. This eliminates the
///    "second root credential with different policy" issue: admin
///    routes now resolve through the normal API-key/SBT pipeline,
///    attribute requests to a user, and lose access immediately when
///    the user is demoted or the key is revoked.
async fn require_admin_auth(state: &AppState, headers: &HeaderMap) -> Result<(), ApiError> {
    use subtle::ConstantTimeEq;

    // Path 1 — env-gated operator key.
    let admin_key = std::env::var("OLYMPUS_ADMIN_KEY").unwrap_or_default();
    if !admin_key.is_empty() {
        if let Some(provided) = headers.get("x-admin-key").and_then(|v| v.to_str().ok()) {
            if bool::from(provided.as_bytes().ct_eq(admin_key.as_bytes())) {
                return Ok(());
            }
        }
    }

    // Path 2 — admin-role + admin-scope API key.
    let pool = db_or_503(state)?;
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
    let now: NaiveDateTime = Utc::now().naive_utc();

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
             AND (k.expires_at IS NULL OR k.expires_at > $2)"#,
    )
    .bind(&key_hash)
    .bind(now)
    .fetch_optional(pool)
    .await
    .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, &format!("DB: {e}")))?
    .ok_or_else(|| err(StatusCode::UNAUTHORIZED, "Admin access required."))?;

    let scopes: Vec<String> = serde_json::from_str(&row.scopes).unwrap_or_default();
    let is_admin_role = row.user_role.as_deref() == Some("admin");
    let has_admin_scope = scopes.iter().any(|s| s == "admin");

    // Match audit L-API-3 policy from `super::admin`: AND, not OR.
    if is_admin_role && has_admin_scope {
        Ok(())
    } else {
        Err(err(StatusCode::FORBIDDEN, "Admin access required."))
    }
}

const VALID_SCOPES: &[&str] = &[
    "read", "write", "ingest", "commit", "verify", "prove", "admin",
];

const VALID_ROLES: &[&str] = &["user", "admin"];

fn validate_scopes(scopes: &[String]) -> Result<(), ApiError> {
    let valid: std::collections::HashSet<&str> = VALID_SCOPES.iter().copied().collect();
    let unknown: Vec<&str> = scopes
        .iter()
        .map(String::as_str)
        .filter(|s| !valid.contains(*s))
        .collect();
    if !unknown.is_empty() {
        return Err(err(
            StatusCode::UNPROCESSABLE_ENTITY,
            &format!(
                "Unknown scope(s): {}. Valid: {}",
                unknown.join(", "),
                VALID_SCOPES.join(", ")
            ),
        ));
    }
    Ok(())
}

// ── GET /admin/users ─────────────────────────────────────────────────────────

#[derive(Debug, Serialize, sqlx::FromRow)]
struct UserKeyRow {
    user_id: String,
    email: String,
    role: String,
    plan: String,
    // `users.created_at` and `api_keys.created_at` are TIMESTAMPTZ in
    // the schema (migration 0010) — decode as DateTime<Utc>, not
    // NaiveDateTime, otherwise sqlx errors with a mismatched-type
    // panic that surfaces as a 500 on every GET /admin/users.
    user_created_at: DateTime<Utc>,
    key_id: Option<String>,
    key_name: Option<String>,
    key_hash_prefix: Option<String>,
    key_scopes: Option<String>,
    key_created_at: Option<DateTime<Utc>>,
}

/// One row per (user, key); users with zero keys appear once with null
/// key fields. Easy to flatten on the frontend.
async fn list_users(
    State(state): State<AppState>,
    headers: HeaderMap,
    _rl: RateLimit,
) -> Result<Json<serde_json::Value>, ApiError> {
    require_admin_auth(&state, &headers).await?;
    let pool = db_or_503(&state)?;

    let rows: Vec<UserKeyRow> = sqlx::query_as(
        "SELECT
             u.id              AS user_id,
             u.email           AS email,
             u.role            AS role,
             u.plan            AS plan,
             u.created_at      AS user_created_at,
             k.id              AS key_id,
             k.name            AS key_name,
             SUBSTRING(k.key_hash FOR 12) AS key_hash_prefix,
             k.scopes          AS key_scopes,
             k.created_at      AS key_created_at
         FROM users u
         LEFT JOIN api_keys k ON k.user_id = u.id
         ORDER BY u.created_at DESC, k.created_at ASC",
    )
    .fetch_all(pool)
    .await
    .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, &format!("DB: {e}")))?;

    Ok(Json(json!({ "rows": rows })))
}

// ── POST /admin/users/{user_id}/keys ────────────────────────────────────────

#[derive(Debug, Deserialize)]
struct MintKeyRequest {
    name: String,
    scopes: Vec<String>,
}

#[derive(Debug, Serialize)]
struct MintKeyResponse {
    /// Raw key — shown ONCE. Caller must save it now.
    raw_key: String,
    key_id: String,
    user_id: String,
    name: String,
    scopes: Vec<String>,
    key_hash: String,
    /// The Baby Jubjub private key the api_key is derived from.
    /// Holders should treat THIS as the master secret — if they lose
    /// `raw_key` but keep `bjj_private_key_hex`, they can re-derive
    /// the API key client-side. Losing both is unrecoverable.
    bjj_private_key_hex: String,
    /// The matching pubkey (also stored in `api_keys.bjj_pubkey_*` so
    /// the server can identify the BJJ identity behind any request
    /// authenticated by this api_key).
    bjj_pubkey_x: String,
    bjj_pubkey_y: String,
}

async fn mint_key_for_user(
    State(state): State<AppState>,
    headers: HeaderMap,
    _rl: RateLimit,
    Path(user_id): Path<String>,
    Json(body): Json<MintKeyRequest>,
) -> Result<Json<MintKeyResponse>, ApiError> {
    require_admin_auth(&state, &headers).await?;
    let pool = db_or_503(&state)?;

    if body.name.trim().is_empty() {
        return Err(err(
            StatusCode::UNPROCESSABLE_ENTITY,
            "name must be non-empty",
        ));
    }
    validate_scopes(&body.scopes)?;

    // Confirm the user exists; surface a clear 404 instead of an opaque
    // foreign-key violation.
    let exists: Option<(String,)> = sqlx::query_as("SELECT id FROM users WHERE id = $1")
        .bind(&user_id)
        .fetch_optional(pool)
        .await
        .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, &format!("DB: {e}")))?;
    if exists.is_none() {
        return Err(err(StatusCode::NOT_FOUND, "user not found"));
    }

    // v0.9 "one master key" unification: every minted API key is now
    // tied to a fresh Baby Jubjub keypair. The api_key is *derived*
    // from the BJJ private key (see derive_api_key_from_bjj), so the
    // recipient has a single secret to keep. We persist the BJJ
    // pubkey on the row so the server can identify the BJJ identity
    // behind any request authed with this api_key — that's the hook
    // for SBT-based capability resolution downstream.
    let mut bjj_priv = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut bjj_priv);
    let bjj_pubkey = crate::zk::witness::baby_jubjub::BabyJubJubPubKey::from_private(&bjj_priv)
        .map_err(|e| {
            err(
                StatusCode::INTERNAL_SERVER_ERROR,
                &format!("BJJ derive: {e}"),
            )
        })?;
    let raw_key = crate::api::middleware::auth::derive_api_key_from_bjj(&bjj_priv);
    let key_hash = blake3_key_hash(&raw_key);
    let key_id = uuid::Uuid::new_v4().to_string();
    let scopes_json = serde_json::to_string(&body.scopes).expect("Vec<String> always serialises");
    let pubkey_x = fr_to_decimal(&bjj_pubkey.x);
    let pubkey_y = fr_to_decimal(&bjj_pubkey.y);

    sqlx::query(
        "INSERT INTO api_keys
             (id, user_id, key_hash, name, scopes, created_at,
              bjj_pubkey_x, bjj_pubkey_y)
         VALUES ($1, $2, $3, $4, $5, NOW(), $6, $7)",
    )
    .bind(&key_id)
    .bind(&user_id)
    .bind(&key_hash)
    .bind(&body.name)
    .bind(&scopes_json)
    .bind(&pubkey_x)
    .bind(&pubkey_y)
    .execute(pool)
    .await
    .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, &format!("DB: {e}")))?;

    Ok(Json(MintKeyResponse {
        raw_key,
        bjj_private_key_hex: hex::encode(bjj_priv),
        bjj_pubkey_x: pubkey_x,
        bjj_pubkey_y: pubkey_y,
        key_id,
        user_id,
        name: body.name,
        scopes: body.scopes,
        key_hash,
    }))
}

// ── PATCH /admin/keys/{key_id}/scopes ───────────────────────────────────────

#[derive(Debug, Deserialize)]
struct UpdateScopesRequest {
    scopes: Vec<String>,
}

async fn update_key_scopes(
    State(state): State<AppState>,
    headers: HeaderMap,
    _rl: RateLimit,
    Path(key_id): Path<String>,
    Json(body): Json<UpdateScopesRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    require_admin_auth(&state, &headers).await?;
    let pool = db_or_503(&state)?;
    validate_scopes(&body.scopes)?;

    let scopes_json = serde_json::to_string(&body.scopes).expect("Vec<String> serialises");
    let updated = sqlx::query("UPDATE api_keys SET scopes = $1 WHERE id = $2")
        .bind(&scopes_json)
        .bind(&key_id)
        .execute(pool)
        .await
        .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, &format!("DB: {e}")))?;

    if updated.rows_affected() == 0 {
        return Err(err(StatusCode::NOT_FOUND, "key not found"));
    }
    Ok(Json(
        json!({ "updated": true, "key_id": key_id, "scopes": body.scopes }),
    ))
}

// ── DELETE /admin/keys/{key_id} ─────────────────────────────────────────────

async fn revoke_key(
    State(state): State<AppState>,
    headers: HeaderMap,
    _rl: RateLimit,
    Path(key_id): Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    require_admin_auth(&state, &headers).await?;
    let pool = db_or_503(&state)?;

    let deleted = sqlx::query("DELETE FROM api_keys WHERE id = $1")
        .bind(&key_id)
        .execute(pool)
        .await
        .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, &format!("DB: {e}")))?;
    if deleted.rows_affected() == 0 {
        return Err(err(StatusCode::NOT_FOUND, "key not found"));
    }
    Ok(Json(json!({ "revoked": true, "key_id": key_id })))
}

// ── PATCH /admin/users/{user_id}/role ───────────────────────────────────────

#[derive(Debug, Deserialize)]
struct UpdateRoleRequest {
    role: String,
}

async fn update_user_role(
    State(state): State<AppState>,
    headers: HeaderMap,
    _rl: RateLimit,
    Path(user_id): Path<String>,
    Json(body): Json<UpdateRoleRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    require_admin_auth(&state, &headers).await?;
    let pool = db_or_503(&state)?;

    if !VALID_ROLES.contains(&body.role.as_str()) {
        return Err(err(
            StatusCode::UNPROCESSABLE_ENTITY,
            &format!("role must be one of: {}", VALID_ROLES.join(", ")),
        ));
    }
    let updated = sqlx::query("UPDATE users SET role = $1 WHERE id = $2")
        .bind(&body.role)
        .bind(&user_id)
        .execute(pool)
        .await
        .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, &format!("DB: {e}")))?;
    if updated.rows_affected() == 0 {
        return Err(err(StatusCode::NOT_FOUND, "user not found"));
    }
    Ok(Json(
        json!({ "updated": true, "user_id": user_id, "role": body.role }),
    ))
}

// ── Router ──────────────────────────────────────────────────────────────────

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/admin/users", get(list_users))
        .route("/admin/users/{user_id}/keys", post(mint_key_for_user))
        .route("/admin/users/{user_id}/role", patch(update_user_role))
        .route("/admin/keys/{key_id}/scopes", patch(update_key_scopes))
        .route("/admin/keys/{key_id}", delete(revoke_key))
}
