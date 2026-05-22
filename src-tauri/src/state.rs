use governor::{DefaultKeyedRateLimiter, Quota, RateLimiter};
use sqlx::PgPool;
use std::net::IpAddr;
use std::num::NonZeroU32;
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
    pub bjj_authority_pubkey: Option<BabyJubJubPubKey>,
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
        let rate_limiter = Arc::new(RateLimiter::keyed(
            Quota::per_minute(NonZeroU32::new(60).expect("60 is nonzero")),
        ));
        let reg_rate_limiter = Arc::new(RateLimiter::keyed(
            Quota::per_minute(NonZeroU32::new(30).expect("30 is nonzero")),
        ));

        let (bjj_authority_key, bjj_authority_pubkey) = match std::env::var("OLYMPUS_BJJ_AUTHORITY_KEY") {
            Ok(hex_str) => {
                match hex::decode(hex_str.trim()) {
                    Ok(bytes) if bytes.len() == 32 => {
                        let mut key = [0u8; 32];
                        key.copy_from_slice(&bytes);
                        match BabyJubJubPubKey::from_private(&key) {
                            Ok(pubkey) => {
                                tracing::info!("BJJ authority key loaded");
                                (Some(key), Some(pubkey))
                            }
                            Err(e) => {
                                tracing::warn!("BJJ authority key invalid: {e}");
                                (None, None)
                            }
                        }
                    }
                    Ok(bytes) => {
                        tracing::warn!("OLYMPUS_BJJ_AUTHORITY_KEY must be 32 bytes, got {}", bytes.len());
                        (None, None)
                    }
                    Err(e) => {
                        tracing::warn!("OLYMPUS_BJJ_AUTHORITY_KEY bad hex: {e}");
                        (None, None)
                    }
                }
            }
            Err(_) => (None, None),
        };

        Self {
            pool,
            db_error,
            started_unix,
            stats_cache: Arc::new(Mutex::new(None)),
            rate_limiter,
            reg_rate_limiter,
            bjj_authority_key,
            bjj_authority_pubkey,
        }
    }
}
