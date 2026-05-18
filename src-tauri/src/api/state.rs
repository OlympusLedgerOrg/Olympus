use std::net::IpAddr;
use std::num::NonZeroU32;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use governor::clock::DefaultClock;
use governor::state::keyed::DefaultKeyedStateStore;
use governor::{Quota, RateLimiter};
use sqlx::PgPool;

/// Shared application state threaded through every Axum handler.
pub struct AppState {
    pub pool: PgPool,
    pub config: Config,
    pub rate_limiter: Arc<RateLimiter<IpAddr, DefaultKeyedStateStore<IpAddr>, DefaultClock>>,
    pub stats_cache: Mutex<Option<StatsCache>>,
}

pub struct Config {
    /// Comma-separated allowed CORS origins (empty = allow all in dev).
    pub cors_origins: Vec<String>,
    /// API keys loaded from `OLYMPUS_API_KEYS_JSON`.
    pub api_keys: Vec<ApiKeyRecord>,
    pub max_upload_bytes: usize,
    pub default_shard_id: String,
}

#[derive(Clone)]
pub struct ApiKeyRecord {
    pub key_id: String,
    /// BLAKE3 hex digest of the raw key.
    pub key_hash: String,
    pub scopes: Vec<String>,
}

pub struct StatsCache {
    pub data: crate::api::public_stats::PublicStats,
    pub fetched_at: Instant,
}

impl StatsCache {
    pub const TTL: Duration = Duration::from_secs(10);

    pub fn is_fresh(&self) -> bool {
        self.fetched_at.elapsed() < Self::TTL
    }
}

impl AppState {
    pub fn new(pool: PgPool) -> Arc<Self> {
        // 60 tokens, 1 refill/second — matches Python defaults.
        let quota = Quota::per_second(NonZeroU32::new(60).unwrap());
        let rate_limiter = Arc::new(RateLimiter::keyed(quota));

        let api_keys = std::env::var("OLYMPUS_API_KEYS_JSON")
            .ok()
            .and_then(|json| serde_json::from_str::<Vec<serde_json::Value>>(&json).ok())
            .unwrap_or_default()
            .into_iter()
            .filter_map(|v| {
                Some(ApiKeyRecord {
                    key_id: v["key_id"].as_str()?.to_owned(),
                    key_hash: v["key_hash"].as_str()?.to_owned(),
                    scopes: v["scopes"]
                        .as_array()?
                        .iter()
                        .filter_map(|s| s.as_str().map(str::to_owned))
                        .collect(),
                })
            })
            .collect();

        Arc::new(Self {
            pool,
            config: Config {
                cors_origins: std::env::var("CORS_ORIGINS")
                    .unwrap_or_default()
                    .split(',')
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .map(str::to_owned)
                    .collect(),
                api_keys,
                max_upload_bytes: 256 * 1024 * 1024,
                default_shard_id: std::env::var("OLYMPUS_DEFAULT_SHARD_ID")
                    .unwrap_or_else(|_| "0x4F3A".into()),
            },
            rate_limiter,
            stats_cache: Mutex::new(None),
        })
    }
}
