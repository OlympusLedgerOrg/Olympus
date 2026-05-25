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
//! `AppState`.  The Axum server only binds to `127.0.0.1` (`server/mod.rs`),
//! so every connection is loopback by construction. We therefore **ignore**
//! the `X-Forwarded-For` header — any local client could otherwise set it
//! to anything and create a fresh rate-limit bucket per spoofed IP, fully
//! defeating the per-IP limiter (audit M-6). The keyed limiter collapses to
//! a single bucket for all callers, which is the correct model for a
//! single-user desktop app.
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
    id: String,
    user_id: String,
    scopes: String,
    name: String,
    bjj_pubkey_x: Option<String>,
    bjj_pubkey_y: Option<String>,
}

// ── SBT-driven scope resolver ────────────────────────────────────────────────
//
// An identity's effective scopes are the union of:
//   * the legacy `api_keys.scopes` column (kept for system-bootstrap and any
//     row predating PR #945's BJJ binding), and
//   * scopes derived from active (non-revoked) SBTs the holder owns,
//     joined via `holder_key = "bjj:{x}:{y}"`.
//
// The mapping is intentionally hardcoded here rather than table-driven —
// scope grants are part of the federation's security policy, not data the
// node operator should mutate from a SQL prompt. If the mapping ever needs
// to be configurable, promote it to `state` and load from a signed manifest.

/// Map a credential's `credential_type` to the scopes it grants.
/// Unknown types grant nothing — fail closed.
fn scopes_for_credential_type(credential_type: &str) -> &'static [&'static str] {
    match credential_type {
        "authority_sbt" => &["admin", "prove", "ingest", "commit", "write", "read", "verify"],
        "press_credential" => &["read", "verify", "ingest", "commit"],
        "foia_requester" => &["read", "verify", "ingest"],
        "court_observer" => &["read", "verify"],
        "verifier_only" => &["read", "verify"],
        _ => &[],
    }
}

/// Query active SBTs for the given BJJ pubkey, verify each row's
/// signature against the trusted-issuer set, and return the union of
/// scopes that PASSED verification.
///
/// Audit H-7: the previous implementation handed scopes out based on
/// row existence alone. A DB-tier compromise could insert a forged
/// `authority_sbt` row and instantly gain admin without a valid
/// signature. Now every row must:
///   (a) carry a populated `issuer_pubkey_{x,y}` and
///       `issued_sig_{r8x,r8y,s}` (rows missing these are skipped — they
///       can't be verified, so they grant no scopes),
///   (b) have an issuer pubkey whose `(x, y)` matches an entry in the
///       trusted-issuer set (today: just the bootstrap-minted
///       `olympus:system` pubkey carried in `AppState`), AND
///   (c) recompute commit_id via `compute_commit_id(holder_key,
///       credential_type, issued_at_unix, details)` and verify the
///       BJJ-EdDSA signature with `baby_jubjub::verify_signature`
///       (which itself enforces R8 + pubkey subgroup membership).
///
/// Returns an empty vec on transient DB error or when the AppState has
/// no `bjj_authority_pubkey` (federation/SBT unprovisioned).
async fn resolve_sbt_scopes(
    pool: &sqlx::PgPool,
    bjj_pubkey_x: &str,
    bjj_pubkey_y: &str,
    trusted_authority: Option<&crate::zk::witness::baby_jubjub::BabyJubJubPubKey>,
) -> Vec<String> {
    use crate::zk::witness::baby_jubjub::{
        self, BabyJubJubPubKey, BabyJubJubSignature,
    };

    let Some(authority) = trusted_authority else {
        // No trusted authority pubkey configured — nothing to verify
        // against. Fail closed: grant no SBT-derived scopes.
        return Vec::new();
    };

    let holder_key = format!("bjj:{}:{}", bjj_pubkey_x, bjj_pubkey_y);

    #[derive(sqlx::FromRow)]
    struct Row {
        credential_type: String,
        commit_id: String,
        details: Option<serde_json::Value>,
        issued_at: chrono::NaiveDateTime,
        issuer_pubkey_x: Option<String>,
        issuer_pubkey_y: Option<String>,
        issued_sig_r8x: Option<String>,
        issued_sig_r8y: Option<String>,
        issued_sig_s: Option<String>,
    }

    let rows: Result<Vec<Row>, _> = sqlx::query_as(
        r#"SELECT credential_type, commit_id, details, issued_at,
                  issuer_pubkey_x, issuer_pubkey_y,
                  issued_sig_r8x, issued_sig_r8y, issued_sig_s
             FROM key_credentials
            WHERE holder_key = $1
              AND revoked_at IS NULL
              AND sbt_nontransferable = TRUE"#,
    )
    .bind(&holder_key)
    .fetch_all(pool)
    .await;

    let rows = match rows {
        Ok(rs) => rs,
        Err(e) => {
            tracing::warn!("resolve_sbt_scopes DB query failed: {e}");
            return Vec::new();
        }
    };

    // Trusted issuer pubkey, pre-canonicalised so we can string-compare
    // without re-parsing for every row.
    let authority_x_dec = fr_to_decimal_local(&authority.x);
    let authority_y_dec = fr_to_decimal_local(&authority.y);

    let mut out: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    for r in rows {
        // (a) Required signature material present?
        let (Some(ix), Some(iy), Some(r8x), Some(r8y), Some(s)) = (
            r.issuer_pubkey_x.as_deref(),
            r.issuer_pubkey_y.as_deref(),
            r.issued_sig_r8x.as_deref(),
            r.issued_sig_r8y.as_deref(),
            r.issued_sig_s.as_deref(),
        ) else {
            tracing::debug!(
                "resolve_sbt_scopes: skipping unsigned credential ({})",
                r.credential_type
            );
            continue;
        };

        // (b) Issuer in the trusted set?
        if ix != authority_x_dec || iy != authority_y_dec {
            tracing::debug!(
                "resolve_sbt_scopes: skipping credential signed by non-trusted issuer ({})",
                r.credential_type
            );
            continue;
        }

        // (c) Recompute commit_id, parse signature, verify.
        let details = r.details.unwrap_or_else(|| serde_json::json!({}));
        let recomputed = crate::api::credentials::compute_commit_id(
            &holder_key,
            &r.credential_type,
            r.issued_at.and_utc().timestamp(),
            &details,
        );
        if hex::encode(recomputed) != r.commit_id {
            tracing::debug!(
                "resolve_sbt_scopes: commit_id mismatch on {} — row tampered or schema drift",
                r.credential_type
            );
            continue;
        }

        let Some(sig) = parse_sig_fields(r8x, r8y, s) else {
            tracing::debug!(
                "resolve_sbt_scopes: malformed signature on {}",
                r.credential_type
            );
            continue;
        };

        let pubkey = BabyJubJubPubKey {
            x: authority.x,
            y: authority.y,
        };
        let msg = digest_to_fr_local(&recomputed);
        if !baby_jubjub::verify_signature(&pubkey, &sig, msg) {
            tracing::warn!(
                "resolve_sbt_scopes: signature verification FAILED on {} — possible tamper",
                r.credential_type
            );
            continue;
        }

        for s in scopes_for_credential_type(&r.credential_type) {
            out.insert((*s).to_owned());
        }
    }
    out.into_iter().collect()
}

/// `Fr` → big-endian decimal string. Local copy to avoid pulling
/// `credentials.rs`'s `fr_to_decimal` (private there).
fn fr_to_decimal_local(f: &ark_bn254::Fr) -> String {
    use ark_ff::{BigInteger, PrimeField};
    let bytes = f.into_bigint().to_bytes_be();
    num_bigint::BigUint::from_bytes_be(&bytes).to_string()
}

/// 32-byte digest → `Fr` via little-endian mod-order reduction.
/// Matches `credentials.rs::digest_to_fr` exactly — the BJJ signature
/// was produced over a value computed this way, so verification has
/// to use the same reduction.
fn digest_to_fr_local(digest: &[u8; 32]) -> ark_bn254::Fr {
    use ark_ff::PrimeField;
    ark_bn254::Fr::from_le_bytes_mod_order(digest)
}

/// Parse the three decimal signature components into a
/// `BabyJubJubSignature`. Returns `None` if any one fails — caller
/// treats that as "skip this row, can't verify".
fn parse_sig_fields(
    r8x: &str,
    r8y: &str,
    s: &str,
) -> Option<crate::zk::witness::baby_jubjub::BabyJubJubSignature> {
    use ark_ff::PrimeField;
    fn parse(s: &str) -> Option<ark_bn254::Fr> {
        let bu: num_bigint::BigUint = s.parse().ok()?;
        Some(ark_bn254::Fr::from_be_bytes_mod_order(&bu.to_bytes_be()))
    }
    Some(crate::zk::witness::baby_jubjub::BabyJubJubSignature {
        r8x: parse(r8x)?,
        r8y: parse(r8y)?,
        s: parse(s)?,
    })
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

/// Deterministically derive the user-visible API key from a 32-byte
/// Baby Jubjub private key.  This is the core of the v0.9 "one master
/// key" unification: the BJJ private key is the *only* secret a holder
/// has to keep safe — the API key is a one-way derivation of it, so
/// losing the API key while keeping the BJJ private key means trivial
/// recovery (re-derive client-side); losing the BJJ key while keeping
/// the API key is recoverable for *this* key's authority but not for
/// any new signature it might want to issue.
///
/// Domain-prefixed BLAKE3 keeps the derivation distinct from any other
/// hash anyone might already be computing over the BJJ private key
/// material — neither the iden3 scalar derivation nor the EdDSA-Poseidon
/// signer uses this prefix, so an attacker who somehow recovers the
/// API-key digest cannot mount a length-extension or related-key
/// attack against the BJJ scalar.
///
/// The format `oly_<hex>` matches the bootstrap shape so existing
/// `X-API-Key:` clients see no change.
pub fn derive_api_key_from_bjj(bjj_priv: &[u8; 32]) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"OLY:APIKEY:V1");
    hasher.update(bjj_priv);
    format!("oly_{}", hex::encode(hasher.finalize().as_bytes()))
}

// ── AuthenticatedKey extractor ────────────────────────────────────────────────

/// Resolved API key, injected by Axum into route handlers that declare it as a
/// parameter.  Requiring this type on a handler enforces that the request
/// carries a valid, non-expired, non-revoked API key.
#[derive(Debug, Clone)]
pub struct AuthenticatedKey {
    /// Primary key of the `api_keys` row (`api_keys.id`) — stored as VARCHAR in DB.
    pub db_id: Uuid,
    /// The owning user (`api_keys.user_id`) — stored as VARCHAR in DB.
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
            r#"SELECT id, user_id, scopes, name, bjj_pubkey_x, bjj_pubkey_y
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
                Json(json!({"detail": format!("Database error: {e}"), "code": "DB_ERROR"})),
            )
        })?
        .ok_or_else(|| {
            (
                StatusCode::UNAUTHORIZED,
                Json(json!({"detail": "Invalid or expired API key.", "code": "AUTH_INVALID"})),
            )
        })?;

        let legacy_scopes: Vec<String> =
            serde_json::from_str(&row.scopes).unwrap_or_default();

        // Union legacy scopes (api_keys.scopes column) with scopes derived
        // from any active SBTs the holder owns. The legacy column is the
        // fallback for system-bootstrap and any pre-#945 row that has no
        // BJJ binding yet.
        let scopes: Vec<String> = match (row.bjj_pubkey_x.as_deref(), row.bjj_pubkey_y.as_deref()) {
            (Some(x), Some(y)) => {
                let sbt_scopes = resolve_sbt_scopes(
                    pool,
                    x,
                    y,
                    state.bjj_authority_pubkey.as_ref(),
                )
                .await;
                let mut merged: std::collections::BTreeSet<String> =
                    legacy_scopes.into_iter().collect();
                merged.extend(sbt_scopes);
                merged.into_iter().collect()
            }
            _ => legacy_scopes,
        };

        let db_id = row.id.parse::<Uuid>().map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"detail": "Corrupt api_keys.id", "code": "DB_ERROR"})),
            )
        })?;
        let user_id = row.user_id.parse::<Uuid>().map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"detail": "Corrupt api_keys.user_id", "code": "DB_ERROR"})),
            )
        })?;

        Ok(AuthenticatedKey {
            db_id,
            user_id,
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

/// Return the client IP used as the rate-limit bucket key.
///
/// Audit M-6: previously this read `X-Forwarded-For` (first hop) and trusted
/// it. The Axum server only binds to `127.0.0.1`, so every connection is
/// loopback and the header has no legitimate sender — but any local process
/// could set it to a fresh address per request and create unlimited
/// rate-limit buckets, fully defeating the per-IP limiter. Always return
/// loopback so the keyed limiter collapses to a single bucket for all
/// callers (the correct model for a single-user desktop app).
pub(crate) fn client_ip(_parts: &Parts) -> IpAddr {
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
    fn scopes_for_credential_type_known_grants() {
        // Authority SBT is the most powerful — must grant admin + all hot-path
        // scopes the routes currently check for.
        let auth = scopes_for_credential_type("authority_sbt");
        for required in ["admin", "prove", "ingest", "commit", "read", "verify"] {
            assert!(
                auth.contains(&required),
                "authority_sbt missing required scope: {required}"
            );
        }
        // Press credential should be the journalist baseline: read + verify +
        // ingest + commit, but never admin or prove.
        let press = scopes_for_credential_type("press_credential");
        assert!(press.contains(&"read"));
        assert!(press.contains(&"verify"));
        assert!(press.contains(&"ingest"));
        assert!(press.contains(&"commit"));
        assert!(!press.contains(&"admin"));
        assert!(!press.contains(&"prove"));
        // Court observer is read-only.
        let court = scopes_for_credential_type("court_observer");
        assert_eq!(court, &["read", "verify"]);
    }

    #[test]
    fn scopes_for_credential_type_unknown_fails_closed() {
        // Unrecognised types grant nothing — never default-open a freshly
        // minted credential type to any scope.
        assert!(scopes_for_credential_type("totally_made_up").is_empty());
        assert!(scopes_for_credential_type("").is_empty());
    }

    #[test]
    fn client_ip_ignores_x_forwarded_for() {
        // Audit M-6 regression guard: a spoofed `X-Forwarded-For` from a local
        // client must NOT create a fresh rate-limit bucket. The keyed limiter
        // collapses to a single bucket for all loopback callers.
        use axum::http::Request;
        let req = Request::builder()
            .header("x-forwarded-for", "10.0.0.1, 192.168.1.1")
            .body(())
            .unwrap();
        let (parts, _) = req.into_parts();
        assert_eq!(client_ip(&parts), IpAddr::from([127, 0, 0, 1]));
    }
}
