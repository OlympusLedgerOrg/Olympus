//! Admin-gated (`x-admin-key`) endpoints: `/key/admin/generate` and
//! `/key/admin/reload-keys`, plus the `require_admin_key` guard.

use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    Json,
};
use rand::RngCore;
use subtle::ConstantTimeEq;

use crate::api::middleware::auth::{blake3_key_hash, RateLimit};
use crate::state::AppState;

use super::common::{db_err, err, ApiError, GenerateKeyRequest, GenerateKeyResponse, VALID_SCOPES};

// ── Helper: admin key guard ───────────────────────────────────────────────────

pub(super) fn require_admin_key(headers: &axum::http::HeaderMap) -> Result<(), ApiError> {
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
    // Compare BLAKE3 digests rather than the raw bytes. `ct_eq` on `&[u8]`
    // short-circuits when the slice lengths differ, which would leak the admin
    // key's length through a timing side channel. Hashing first reduces both
    // operands to fixed 32-byte digests, so the comparison is constant-time over
    // its whole domain regardless of the provided value's length. Mirrors
    // `api::middleware::auth::require_admin_auth`.
    let provided_digest = blake3::hash(provided.as_bytes());
    let expected_digest = blake3::hash(admin_key.as_bytes());
    if !bool::from(
        provided_digest
            .as_bytes()
            .as_slice()
            .ct_eq(expected_digest.as_bytes().as_slice()),
    ) {
        return Err(err(StatusCode::UNAUTHORIZED, "Invalid admin key."));
    }
    Ok(())
}

// ── Route: POST /key/admin/generate ──────────────────────────────────────────

/// Generate a new API key and return the raw key + BLAKE3 hash + env-var entry.
///
/// Protected by `X-Admin-Key`.  The raw key is returned once — the caller must
/// store it.  The `env_entry` field is the JSON blob to add to
/// `OLYMPUS_API_KEYS_JSON` (legacy env-var auth path) or to feed into
/// `POST /auth/admin/users` for DB-backed auth.
///
/// This endpoint performs no DB write — it is a pure key-material generator.
pub(super) async fn admin_generate_key(
    headers: HeaderMap,
    _rl: RateLimit,
    Json(body): Json<GenerateKeyRequest>,
) -> Result<Json<GenerateKeyResponse>, ApiError> {
    require_admin_key(&headers)?;

    // Validate scopes.
    let valid_set: std::collections::HashSet<&str> = VALID_SCOPES.iter().copied().collect();
    let unknown: Vec<&str> = body
        .scopes
        .iter()
        .map(String::as_str)
        .filter(|s| !valid_set.contains(*s))
        .collect();
    if !unknown.is_empty() {
        return Err(err(
            StatusCode::UNPROCESSABLE_ENTITY,
            &format!("Unknown scope(s): {}", unknown.join(", ")),
        ));
    }

    // Validate expires_at parses.
    let normalised = body.expires_at.replace('Z', "+00:00");
    chrono::DateTime::parse_from_rfc3339(&normalised).map_err(|_| {
        err(
            StatusCode::UNPROCESSABLE_ENTITY,
            "expires_at must be ISO 8601, e.g. 2027-01-01T00:00:00Z",
        )
    })?;

    let mut raw_bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut raw_bytes);
    let raw_key = hex::encode(raw_bytes);
    let key_hash = blake3_key_hash(&raw_key);

    let entry = serde_json::json!({
        "key_hash": key_hash,
        "key_id":   body.name,
        "scopes":   body.scopes,
        "expires_at": body.expires_at,
    });

    Ok(Json(GenerateKeyResponse {
        raw_key,
        key_hash,
        key_id: body.name.clone(),
        scopes: body.scopes,
        expires_at: body.expires_at,
        env_entry: serde_json::to_string(&entry).expect("json serialisation"),
    }))
}

// ── Route: POST /key/admin/reload-keys ───────────────────────────────────────

/// Verify admin auth and report the current active API-key count from the DB.
///
/// The Python counterpart hot-reloads `OLYMPUS_API_KEYS_JSON` from the
/// environment (env-var-based auth).  The Tauri version is DB-backed and has
/// no in-memory key store to reload; this endpoint acts as an admin-verified
/// health check and returns the live DB count.
pub(super) async fn admin_reload_keys(
    State(state): State<AppState>,
    headers: HeaderMap,
    _rl: RateLimit,
) -> Result<Json<serde_json::Value>, ApiError> {
    require_admin_key(&headers)?;

    let pool = state
        .pool
        .as_ref()
        .ok_or_else(|| err(StatusCode::SERVICE_UNAVAILABLE, "Database unavailable."))?;

    // Mirror the auth predicate (auth.rs): a NULL expires_at means "never
    // expires" and such keys ARE live, so `expires_at > NOW()` alone would
    // undercount every admin-minted key (which has no expiry).
    let count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM api_keys \
         WHERE revoked_at IS NULL AND (expires_at IS NULL OR expires_at > NOW())",
    )
    .fetch_one(pool)
    .await
    .map_err(db_err)?;

    Ok(Json(serde_json::json!({
        "reloaded": true,
        "key_count": count,
    })))
}
