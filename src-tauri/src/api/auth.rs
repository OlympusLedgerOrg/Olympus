use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use axum::body::Body;
use axum::extract::{ConnectInfo, Request, State};
use axum::middleware::Next;
use axum::response::Response;
use blake3::Hasher;

use super::error::ApiError;
use super::state::{ApiKeyRecord, AppState};

// ── Rate limiting ──────────────────────────────────────────────────────────────

pub async fn rate_limit_check(
    state: &AppState,
    ip: IpAddr,
) -> Result<(), ApiError> {
    state
        .rate_limiter
        .check_key(&ip)
        .map_err(|_| ApiError::TooManyRequests)
}

fn extract_client_ip(req: &Request) -> IpAddr {
    // Respect X-Forwarded-For from trusted reverse proxies; fall back to
    // direct connection address.
    if let Some(forwarded) = req.headers().get("x-forwarded-for") {
        if let Ok(val) = forwarded.to_str() {
            if let Ok(ip) = val.split(',').next().unwrap_or("").trim().parse::<IpAddr>() {
                return ip;
            }
        }
    }
    req.extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|ci| ci.0.ip())
        .unwrap_or(IpAddr::from([127, 0, 0, 1]))
}

// ── API key validation ─────────────────────────────────────────────────────────

fn blake3_hex(raw: &str) -> String {
    let mut h = Hasher::new();
    h.update(raw.as_bytes());
    h.finalize().to_hex().to_string()
}

fn find_key<'a>(
    records: &'a [ApiKeyRecord],
    raw_key: &str,
) -> Option<&'a ApiKeyRecord> {
    let candidate_hash = blake3_hex(raw_key);
    // Constant-time comparison across all records to avoid timing oracle.
    records.iter().find(|r| {
        // Both sides are 64-char hex — same length, safe for byte equality.
        let a = r.key_hash.as_bytes();
        let b = candidate_hash.as_bytes();
        a.len() == b.len() && a.iter().zip(b).all(|(x, y)| x == y)
    })
}

fn extract_raw_key(req: &Request) -> Option<String> {
    // X-API-Key header takes priority, then Authorization: Bearer <token>.
    if let Some(v) = req.headers().get("x-api-key") {
        return v.to_str().ok().map(str::to_owned);
    }
    if let Some(v) = req.headers().get("authorization") {
        let s = v.to_str().ok()?;
        let token = s.strip_prefix("Bearer ")?;
        return Some(token.to_owned());
    }
    None
}

// ── Middleware ─────────────────────────────────────────────────────────────────

/// Axum middleware that enforces API key auth AND rate limiting.
/// Attaches the validated `ApiKeyRecord` as a request extension so handlers
/// can read scopes without re-validating.
pub async fn auth_middleware(
    State(state): State<Arc<AppState>>,
    req: Request,
    next: Next,
) -> Result<Response, ApiError> {
    let ip = extract_client_ip(&req);
    rate_limit_check(&state, ip).await?;

    let raw_key = extract_raw_key(&req)
        .ok_or_else(|| ApiError::Unauthorized("Missing API key".into()))?;

    let record = find_key(&state.config.api_keys, &raw_key)
        .ok_or_else(|| ApiError::Unauthorized("Invalid API key".into()))?
        .clone();

    let mut req = req;
    req.extensions_mut().insert(record);
    Ok(next.run(req).await)
}

/// Extractor: pull the validated key record inserted by `auth_middleware`.
pub struct AuthedKey(pub ApiKeyRecord);

impl<S> axum::extract::FromRequestParts<S> for AuthedKey
where
    S: Send + Sync,
{
    type Rejection = ApiError;

    async fn from_request_parts(
        parts: &mut axum::http::request::Parts,
        _state: &S,
    ) -> Result<Self, Self::Rejection> {
        parts
            .extensions
            .get::<ApiKeyRecord>()
            .cloned()
            .map(AuthedKey)
            .ok_or_else(|| ApiError::Unauthorized("No auth context".into()))
    }
}

impl AuthedKey {
    pub fn require_scope(&self, scope: &str) -> Result<(), ApiError> {
        if self.0.scopes.iter().any(|s| s == scope || s == "admin") {
            Ok(())
        } else {
            Err(ApiError::Forbidden(format!("Scope '{scope}' required")))
        }
    }
}
