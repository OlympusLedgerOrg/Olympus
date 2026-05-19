use sqlx::PgPool;
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
}

impl AppState {
    pub fn new(pool: Option<PgPool>) -> Self {
        let started_unix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;
        Self {
            pool,
            started_unix,
            stats_cache: Arc::new(Mutex::new(None)),
        }
    }
}
