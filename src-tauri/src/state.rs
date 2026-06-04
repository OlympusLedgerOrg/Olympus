use governor::{DefaultKeyedRateLimiter, Quota, RateLimiter};
use sqlx::PgPool;
use std::net::IpAddr;
use std::num::NonZeroU32;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::Mutex;

use crate::zk::witness::baby_jubjub::BabyJubJubPubKey;

/// Cached result with the instant it was stored.
pub struct Cached<T> {
    pub value: T,
    pub stored_at: std::time::Instant,
}

/// Shared application state threaded through the Axum router.
#[derive(Clone)]
pub struct AppState {
    /// Postgres connection pool. None when DATABASE_URL is absent or unreachable.
    pub pool: Option<PgPool>,
    /// Human-readable reason the database failed to start, if any.
    /// Surfaced via /health and the `get_db_status` Tauri command so the UI
    /// can show a blocking error instead of silently returning 503s.
    pub db_error: Option<String>,
    /// Unix timestamp (seconds) when the server process started — used for uptime.
    pub started_unix: i64,
    /// 10-second TTL cache for /public/stats.
    pub stats_cache: Arc<Mutex<Option<Cached<crate::routes::public_stats::PublicStats>>>>,
    /// General per-IP rate limiter: 60 req/min.
    ///
    /// Uses `governor::DefaultClock` which is backed by `std::time::Instant`.
    /// On WSL2, clock drift versus the Windows host can cause transient 429s.
    /// Fix: `sudo hwclock -s` to re-sync the realtime clock.
    pub rate_limiter: Arc<DefaultKeyedRateLimiter<IpAddr>>,
    /// Stricter per-IP rate limiter for registration/login: 30 req/min by
    /// default (overridable via env; see `quota_per_min` in
    /// [`AppState::new_with_error`]).
    pub reg_rate_limiter: Arc<DefaultKeyedRateLimiter<IpAddr>>,
    /// Server-side Baby JubJub authority key for ZK unified circuit signing.
    /// Loaded from `OLYMPUS_BJJ_AUTHORITY_KEY` (32-byte hex) at startup.
    /// `None` when the env var is absent — unified proves will return 503.
    pub bjj_authority_key: Option<[u8; 32]>,
    /// Cached BJJ public key derived from `bjj_authority_key`.
    ///
    /// This is the *primary* trusted issuer (used to sign newly-issued
    /// SBTs and to verify the most recent ones). The full SBT-acceptance
    /// set is [`Self::bjj_trusted_issuers`], which always begins with this
    /// pubkey and may include additional, older issuer pubkeys loaded from
    /// `OLYMPUS_BJJ_TRUSTED_ISSUERS_JSON` (audit M-3).
    pub bjj_authority_pubkey: Option<BabyJubJubPubKey>,
    /// Full set of issuer pubkeys whose SBTs are accepted by the scope
    /// resolver, in priority order (primary first). Loaded once at startup
    /// from `OLYMPUS_BJJ_TRUSTED_ISSUERS_JSON` (a JSON array of
    /// `{"x":"...","y":"...","valid_from":<unix?>,"valid_until":<unix?>}`
    /// entries) and unioned with the bootstrap-minted primary pubkey.
    /// Audit M-3: without this, a lost or rotated BJJ authority key would
    /// invalidate every existing SBT in one shot.
    pub bjj_trusted_issuers: Vec<crate::api::trusted_issuers::TrustedIssuer>,
    /// Ed25519 signing key for redaction-bundle signatures (`POST
    /// /redaction/issue`). Resolved once at startup by
    /// [`resolve_ingest_signing_key`]: explicit `OLYMPUS_INGEST_SIGNING_KEY`
    /// (or `OLYMPUS_DEV_SIGNING_KEY`) hex32 takes precedence; otherwise, in
    /// dev, a stable key is derived from the persisted BJJ authority so a
    /// fresh checkout can sign redaction bundles without extra env setup.
    /// `None` only in production with no explicit key — signing callers then
    /// fail closed with 503, preserving the "persist your signing key"
    /// invariant (production keys must be operator-provided and independent).
    pub ingest_signing_key: Option<[u8; 32]>,
    /// Resolved on-disk location of the ZK circuit artifacts
    /// (`<circuit>.wasm`, `<circuit>.r1cs`, `<circuit>.ark.zkey`,
    /// `verification_keys/<circuit>_vkey.json`).
    /// Set at startup by main.rs from (in order): `OLYMPUS_PROOFS_DIR`,
    /// the Tauri resource dir, an exe-relative `proofs/keys`, or the
    /// repo-relative dev fallback. `None` when no candidate is populated —
    /// `/zk/prove` and `/zk/verify` return 503 with a clear message.
    pub proofs_dir: Option<PathBuf>,
    /// Ingest parser provenance (ADR-0003 / ADR-0004), resolved once at
    /// startup from `OLYMPUS_INGEST_PARSER_ID` /
    /// `INGEST_PARSER_CANONICAL_VERSION` / `OLYMPUS_INGEST_MODEL_HASH`. Every
    /// leaf committed into the parser-bound SMT is stamped with this triple so
    /// the ledger records which parser + model produced each value.
    pub ingest_provenance: crate::ingest_provenance::IngestProvenance,
    /// External anchoring config (RFC 3161 / Rekor / OTS). Resolved once
    /// at startup from `OLYMPUS_ANCHOR_*` env vars. All-`None` config is
    /// the default and disables outbound anchoring submissions.
    pub anchoring: crate::anchoring::AnchoringConfig,
    /// Shared reqwest client used by the anchoring backends — bypasses
    /// reqwest's per-call connection pool warm-up for hot paths like
    /// the gossip loop that anchor each checkpoint.
    pub anchor_http: Arc<reqwest::Client>,
    /// P2P federation config (Tor hidden service, gossip interval).
    #[cfg(feature = "federation")]
    pub federation_config: Option<crate::federation::FederationConfig>,
    /// Filesystem location of the arti hidden-service state. Required
    /// by `POST /federation/identity/rotate` (audit M-F2) to wipe the
    /// persisted HS key material. `None` when federation has never
    /// been bootstrapped — the rotate route 503s in that case.
    #[cfg(feature = "federation")]
    pub federation_state_dir: Option<PathBuf>,
    /// Outbound Tor client handle, populated once the hidden service has
    /// bootstrapped (see `main.rs`). Issue-time quorum co-signature
    /// collection (`federation::cosign::collect_cosignatures`) reaches
    /// peers' `.onion` co-sign endpoints through this. A plain HTTP client
    /// can't resolve `.onion`, so quorum issuance returns 503 until this is
    /// set. Shared `OnceCell` because the bootstrap completes asynchronously
    /// *after* `AppState` is already moved into the server.
    #[cfg(feature = "federation")]
    pub tor_handle: Arc<tokio::sync::OnceCell<Arc<crate::federation::tor::TorHandle>>>,
}

impl AppState {
    pub fn new(pool: Option<PgPool>) -> Self {
        Self::new_with_error(pool, None)
    }

    pub fn new_with_error(pool: Option<PgPool>, db_error: Option<String>) -> Self {
        let started_unix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;

        // Per-minute quotas. Defaults (60 general / 30 registration) match
        // the long-standing values; both are overridable via env so operators
        // behind a trusted proxy can tune them — and so the integration-test
        // harness, where dozens of tests share one loopback bucket, can raise
        // them out of the way (`OLYMPUS_RATE_LIMIT_PER_MIN` /
        // `OLYMPUS_REG_RATE_LIMIT_PER_MIN`). A non-numeric or zero value falls
        // back to the default.
        fn quota_per_min(var: &str, default: u32) -> Quota {
            let n = std::env::var(var)
                .ok()
                .and_then(|v| v.trim().parse::<u32>().ok())
                .and_then(NonZeroU32::new)
                .unwrap_or_else(|| NonZeroU32::new(default).expect("default is nonzero"));
            Quota::per_minute(n)
        }
        let rate_limiter = Arc::new(RateLimiter::keyed(quota_per_min(
            "OLYMPUS_RATE_LIMIT_PER_MIN",
            60,
        )));
        let reg_rate_limiter = Arc::new(RateLimiter::keyed(quota_per_min(
            "OLYMPUS_REG_RATE_LIMIT_PER_MIN",
            30,
        )));

        Self {
            pool,
            db_error,
            started_unix,
            stats_cache: Arc::new(Mutex::new(None)),
            rate_limiter,
            reg_rate_limiter,
            bjj_authority_key: None,
            bjj_authority_pubkey: None,
            bjj_trusted_issuers: Vec::new(),
            ingest_signing_key: None,
            proofs_dir: None,
            ingest_provenance: crate::ingest_provenance::IngestProvenance::from_env(),
            anchoring: crate::anchoring::AnchoringConfig::from_env(),
            anchor_http: crate::anchoring::build_http_client(std::time::Duration::from_secs(30)),
            #[cfg(feature = "federation")]
            federation_config: None,
            #[cfg(feature = "federation")]
            federation_state_dir: None,
            #[cfg(feature = "federation")]
            tor_handle: Arc::new(tokio::sync::OnceCell::new()),
        }
    }
}

/// Resolve the Ed25519 ingest/redaction signing key once at startup.
///
/// Precedence:
///  1. `OLYMPUS_INGEST_SIGNING_KEY` (32-byte hex) — the persistent,
///     operator-provided key. Required in production.
///  2. `OLYMPUS_DEV_SIGNING_KEY` when it holds 32-byte hex (explicit dev key).
///  3. **Dev only** — a stable key derived from the persisted BJJ authority
///     via domain-separated BLAKE3, so a fresh checkout can sign redaction
///     bundles without any extra setup. It persists exactly as long as the
///     BJJ authority does (which is persisted across restarts), satisfying the
///     "signing keys must be persisted" invariant for local development.
///
/// Returns `None` in production when no explicit key is configured — callers
/// (e.g. `POST /redaction/issue`) then fail closed with 503 rather than
/// silently minting signatures under an ephemeral key. The dev derivation is
/// deliberately skipped in production so the redaction signing key stays an
/// independent, operator-controlled secret there (not coupled to the BJJ key).
pub fn resolve_ingest_signing_key(bjj_authority_key: Option<&[u8; 32]>) -> Option<[u8; 32]> {
    fn parse_hex32(s: &str) -> Option<[u8; 32]> {
        let mut out = [0u8; 32];
        hex::decode_to_slice(s.trim(), &mut out).ok().map(|()| out)
    }
    for var in ["OLYMPUS_INGEST_SIGNING_KEY", "OLYMPUS_DEV_SIGNING_KEY"] {
        if let Ok(h) = std::env::var(var) {
            if let Some(key) = parse_hex32(&h) {
                return Some(key);
            }
        }
    }
    let is_prod = std::env::var("OLYMPUS_ENV")
        .map(|v| v.eq_ignore_ascii_case("production"))
        .unwrap_or(false);
    if is_prod {
        return None;
    }
    bjj_authority_key.map(derive_dev_ingest_key)
}

/// Domain-separated derivation of the dev-only Ed25519 ingest signing key from
/// the persisted BJJ authority. Pure (no env / IO) so it is unit-testable
/// without mutating the shared process environment.
fn derive_dev_ingest_key(bjj_authority_key: &[u8; 32]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"OLY:INGEST:ED25519:DEV:V1");
    hasher.update(bjj_authority_key);
    *hasher.finalize().as_bytes()
}

#[cfg(test)]
mod ingest_signing_key_tests {
    use super::derive_dev_ingest_key;

    #[test]
    fn dev_derivation_is_stable_nonzero_and_binds_to_bjj() {
        let a = derive_dev_ingest_key(&[7u8; 32]);
        // Deterministic — same BJJ key always yields the same signing key, so
        // historical redaction signatures stay verifiable across restarts.
        assert_eq!(a, derive_dev_ingest_key(&[7u8; 32]));
        assert_ne!(a, [0u8; 32]);
        // Distinct BJJ authority → distinct derived key (no cross-instance reuse).
        assert_ne!(a, derive_dev_ingest_key(&[8u8; 32]));
    }
}
