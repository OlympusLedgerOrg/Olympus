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
    /// Stricter per-IP rate limiter for registration/login: 2 req/min.
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
    /// Resolved on-disk location of the ZK circuit artifacts
    /// (`<circuit>.wasm`, `<circuit>.r1cs`, `<circuit>.ark.zkey`,
    /// `verification_keys/<circuit>_vkey.json`).
    /// Set at startup by main.rs from (in order): `OLYMPUS_PROOFS_DIR`,
    /// the Tauri resource dir, an exe-relative `proofs/keys`, or the
    /// repo-relative dev fallback. `None` when no candidate is populated —
    /// `/zk/prove` and `/zk/verify` return 503 with a clear message.
    pub proofs_dir: Option<PathBuf>,
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

        // SAFETY: literal NonZero constants; these can never be zero.
        let rate_limiter = Arc::new(RateLimiter::keyed(Quota::per_minute(
            NonZeroU32::new(60).expect("60 is nonzero"),
        )));
        let reg_rate_limiter = Arc::new(RateLimiter::keyed(Quota::per_minute(
            NonZeroU32::new(30).expect("30 is nonzero"),
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
            proofs_dir: None,
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
