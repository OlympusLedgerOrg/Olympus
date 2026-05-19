use governor::{DefaultKeyedRateLimiter, Quota, RateLimiter};
use sqlx::PgPool;
use std::net::IpAddr;
use std::num::NonZeroU32;
use std::sync::Arc;
use tokio::sync::Mutex;

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
}

impl AppState {
    pub fn new(pool: Option<PgPool>) -> Self {
        let started_unix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;

        // SAFETY: literal NonZero constants; these can never be zero.
        let rate_limiter = Arc::new(RateLimiter::keyed(
            Quota::per_minute(NonZeroU32::new(60).expect("60 is nonzero")),
        ));
        let reg_rate_limiter = Arc::new(RateLimiter::keyed(
            Quota::per_minute(NonZeroU32::new(2).expect("2 is nonzero")),
        ));

        Self {
            pool,
            started_unix,
            stats_cache: Arc::new(Mutex::new(None)),
            rate_limiter,
            reg_rate_limiter,
        }
    }
}
