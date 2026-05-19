//! Axum extractors for API-key authentication and per-IP rate limiting.
//!
//! # Auth flow
//!
//! 1. Extract raw key from `X-API-Key` header or `Authorization: Bearer <token>`.
//! 2. Compute `BLAKE3(raw_key.as_bytes())` — identical to Python's `_hash_key`.
//! 3. `SELECT … FROM api_keys WHERE key_hash = $1 AND revoked_at IS NULL
//!    AND (expires_at IS NULL OR expires_at > NOW())`.
//! 4. Deserialise the JSON `scopes` column into `Vec<String>`.
//!
//! # Rate limiting
//!
//! `RateLimit` and `RegistrationRateLimit` are thin extractors that call into
//! the `governor::DefaultKeyedRateLimiter<IpAddr>` instances stored in
//! `AppState`.  Both prefer `X-Forwarded-For`; the desktop app always runs
//! locally so the fallback is `127.0.0.1`.
//!
//! WSL2 note: governor uses `std::time::Instant` (DefaultClock).  If the WSL2
//! clock drifts from the Windows host, tokens may appear exhausted until you
//! run `sudo hwclock -s`.  See state.rs for the full comment.

use std::net::IpAddr;

use axum::{
    extract::FromRef,
    http::{request::Parts, StatusCode},
    Json,
};
use serde_json::{json, Value};
use uuid::Uuid;

use crate::state::AppState;

// ── Row types ────────────────────────────────────────────────────────────────

#[derive(sqlx::FromRow)]
struct ApiKeyRow {
    id: Uuid,
    user_id: Uuid,
    scopes: String,
    name: String,
}

// ── Public key-hash helper ────────────────────────────────────────────────────

/// Compute the BLAKE3 hex digest of a raw API key string.
///
/// Matches `_hash_key` / `hash_bytes(raw.encode()).hex()` in `api/auth.py` and
/// `api/routers/user_auth.py`.  No domain prefix — API key material is hashed
/// plain; OLY: prefixes are only for Merkle leaf/node hashing.
pub fn blake3_key_hash(raw: &str) -> String {
    blake3::hash(raw.as_bytes()).to_hex().to_string()
}

// ── AuthenticatedKey extractor ────────────────────────────────────────────────

/// Resolved API key, injected by Axum into route handlers that declare it as a
/// parameter.  Requiring this type on a handler enforces that the request
/// carries a valid, non-expired, non-revoked API key.
#[derive(Debug, Clone)]
pub struct AuthenticatedKey {
    /// Primary key of the `api_keys` row (`api_keys.id`).
    pub db_id: Uuid,
    /// The owning user (`api_keys.user_id`).
    pub user_id: Uuid,
    /// Decoded scopes (e.g. `["read", "verify"]`).
    pub scopes: Vec<String>,
    /// Human-readable key name.
    pub name: String,
}

impl AuthenticatedKey {
    /// Return `true` when the key carries `scope`.
    pub fn has_scope(&self, scope: &str) -> bool {
        self.scopes.iter().any(|s| s == scope)
    }
}

impl<S> axum::extract::FromRequestParts<S> for AuthenticatedKey
where
    S: Send + Sync,
    AppState: FromRef<S>,
{
    type Rejection = (StatusCode, Json<Value>);

    async fn from_request_parts(
        parts: &mut Parts,
        state: &S,
    ) -> Result<Self, Self::Rejection> {
        let state = AppState::from_ref(state);

        let raw = extract_raw_key(parts).ok_or_else(|| {
            (
                StatusCode::UNAUTHORIZED,
                Json(json!({"detail": "API key required.", "code": "AUTH_MISSING"})),
            )
        })?;

        let pool = state.pool.as_ref().ok_or_else(|| {
            (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(json!({"detail": "Database unavailable.", "code": "DB_UNAVAILABLE"})),
            )
        })?;

        let key_hash = blake3_key_hash(&raw);

        let row = sqlx::query_as::<_, ApiKeyRow>(
            r#"SELECT id, user_id, scopes, name
               FROM api_keys
               WHERE key_hash = $1
                 AND revoked_at IS NULL
                 AND (expires_at IS NULL OR expires_at > NOW())"#,
        )
        .bind(&key_hash)
        .fetch_optional(pool)
        .await
        .map_err(|e| {
            tracing::error!("auth DB query failed: {e}");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"detail": "Database error.", "code": "DB_ERROR"})),
            )
        })?
        .ok_or_else(|| {
            (
                StatusCode::UNAUTHORIZED,
                Json(json!({"detail": "Invalid or expired API key.", "code": "AUTH_INVALID"})),
            )
        })?;

        let scopes: Vec<String> =
            serde_json::from_str(&row.scopes).unwrap_or_default();

        Ok(AuthenticatedKey {
            db_id: row.id,
            user_id: row.user_id,
            scopes,
            name: row.name,
        })
    }
}

// ── RateLimit extractor (60 req/min per IP) ──────────────────────────────────

/// General-purpose rate-limit guard.  Attach to any route that should be
/// capped at 60 requests per minute per client IP.
pub struct RateLimit;

impl<S> axum::extract::FromRequestParts<S> for RateLimit
where
    S: Send + Sync,
    AppState: FromRef<S>,
{
    type Rejection = (StatusCode, Json<Value>);

    async fn from_request_parts(
        parts: &mut Parts,
        state: &S,
    ) -> Result<Self, Self::Rejection> {
        let state = AppState::from_ref(state);
        let ip = client_ip(parts);

        state.rate_limiter.check_key(&ip).map_err(|_| {
            (
                StatusCode::TOO_MANY_REQUESTS,
                Json(json!({"detail": "Rate limit exceeded.", "code": "RATE_LIMITED"})),
            )
        })?;

        Ok(RateLimit)
    }
}

// ── RegistrationRateLimit extractor (2 req/min per IP) ───────────────────────

/// Stricter rate-limit guard for registration, login, and recovery endpoints.
/// Matches Python's `registration_rate_limit` (1/min, 10/day) — simplified to
/// 2/min for Phase 2B; day-bucket can be added in a follow-up.
pub struct RegistrationRateLimit;

impl<S> axum::extract::FromRequestParts<S> for RegistrationRateLimit
where
    S: Send + Sync,
    AppState: FromRef<S>,
{
    type Rejection = (StatusCode, Json<Value>);

    async fn from_request_parts(
        parts: &mut Parts,
        state: &S,
    ) -> Result<Self, Self::Rejection> {
        let state = AppState::from_ref(state);
        let ip = client_ip(parts);

        state.reg_rate_limiter.check_key(&ip).map_err(|_| {
            (
                StatusCode::TOO_MANY_REQUESTS,
                Json(json!({"detail": "Rate limit exceeded.", "code": "RATE_LIMITED"})),
            )
        })?;

        Ok(RegistrationRateLimit)
    }
}

// ── Internal helpers ──────────────────────────────────────────────────────────

fn extract_raw_key(parts: &Parts) -> Option<String> {
    if let Some(val) = parts.headers.get("x-api-key") {
        return val.to_str().ok().map(str::to_owned);
    }
    let auth = parts.headers.get("authorization")?.to_str().ok()?;
    let token = auth
        .strip_prefix("Bearer ")
        .or_else(|| auth.strip_prefix("bearer "))?
        .trim();
    if token.is_empty() {
        None
    } else {
        Some(token.to_owned())
    }
}

/// Resolve the client IP from `X-Forwarded-For` (first hop) or fall back to
/// `127.0.0.1`.  The desktop app always runs locally, so the fallback is safe.
pub(crate) fn client_ip(parts: &Parts) -> IpAddr {
    if let Some(fwd) = parts.headers.get("x-forwarded-for") {
        if let Ok(s) = fwd.to_str() {
            if let Some(first) = s.split(',').next() {
                if let Ok(ip) = first.trim().parse() {
                    return ip;
                }
            }
        }
    }
    IpAddr::from([127, 0, 0, 1])
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blake3_key_hash_is_hex_64_chars() {
        let h = blake3_key_hash("some-raw-key");
        assert_eq!(h.len(), 64, "BLAKE3 hex digest must be 64 characters");
        assert!(h.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn blake3_key_hash_deterministic() {
        let raw = "test-api-key-abc123";
        assert_eq!(blake3_key_hash(raw), blake3_key_hash(raw));
    }

    #[test]
    fn blake3_key_hash_differs_for_different_keys() {
        assert_ne!(blake3_key_hash("key-a"), blake3_key_hash("key-b"));
    }

    #[test]
    fn client_ip_falls_back_to_loopback() {
        use axum::http::Request;
        let req = Request::builder().body(()).unwrap();
        let (mut parts, _) = req.into_parts();
        assert_eq!(client_ip(&mut parts), IpAddr::from([127, 0, 0, 1]));
    }

    #[test]
    fn client_ip_reads_x_forwarded_for() {
        use axum::http::Request;
        let req = Request::builder()
            .header("x-forwarded-for", "10.0.0.1, 192.168.1.1")
            .body(())
            .unwrap();
        let (mut parts, _) = req.into_parts();
        assert_eq!(client_ip(&mut parts), "10.0.0.1".parse::<IpAddr>().unwrap());
    }
}
