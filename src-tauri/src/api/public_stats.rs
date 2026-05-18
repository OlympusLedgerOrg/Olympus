use std::sync::Arc;
use std::time::Instant;

use axum::extract::State;
use axum::Json;
use serde::Serialize;

use super::error::ApiResult;
use super::state::{AppState, StatsCache};

#[derive(Debug, Clone, Serialize)]
pub struct PublicStats {
    pub copies: i64,
    pub shards: i64,
    pub proofs: i64,
    pub sbts: i64,
    pub nodes: i64,
    pub uptime: String,
    pub uptime_seconds: u64,
}

static START: std::sync::OnceLock<Instant> = std::sync::OnceLock::new();

pub async fn get_stats(
    State(state): State<Arc<AppState>>,
) -> ApiResult<Json<PublicStats>> {
    let start = START.get_or_init(Instant::now);

    // Return cached value if still fresh.
    {
        let cache = state.stats_cache.lock().unwrap();
        if let Some(c) = cache.as_ref() {
            if c.is_fresh() {
                return Ok(Json(c.data.clone()));
            }
        }
    }

    let stats = fetch_stats(&state).await?;

    let elapsed = start.elapsed();
    let uptime_seconds = elapsed.as_secs();
    let stats = PublicStats {
        uptime_seconds,
        uptime: format_uptime(uptime_seconds),
        ..stats
    };

    *state.stats_cache.lock().unwrap() = Some(StatsCache {
        data: stats.clone(),
        fetched_at: Instant::now(),
    });

    Ok(Json(stats))
}

async fn fetch_stats(state: &AppState) -> ApiResult<PublicStats> {
    let pool = &state.pool;

    // Each counter tries candidate table names in order, settling on the
    // first that exists — mirrors the Python fallback chain.
    let copies = count_first_existing(
        pool,
        &["ledger_entries", "cdhs_smf_leaves", "ingest_records", "records"],
    )
    .await;

    let shards = count_distinct_first_existing(
        pool,
        "shard_id",
        &["shard_headers", "ingestion_proofs", "smt_leaves"],
    )
    .await;

    let proofs = count_first_existing(
        pool,
        &["ingestion_proofs", "zk_proofs", "proofs"],
    )
    .await;

    let sbts = count_first_existing(pool, &["key_credentials", "sbts"]).await;
    let nodes = count_first_existing(pool, &["agencies", "nodes"]).await;

    Ok(PublicStats {
        copies,
        shards,
        proofs,
        sbts,
        nodes,
        uptime: String::new(),
        uptime_seconds: 0,
    })
}

async fn count_first_existing(pool: &sqlx::PgPool, tables: &[&str]) -> i64 {
    for table in tables {
        let q = format!("SELECT COUNT(*) FROM \"{}\"", table);
        if let Ok(row) = sqlx::query_scalar::<_, i64>(&q).fetch_one(pool).await {
            return row;
        }
    }
    0
}

async fn count_distinct_first_existing(
    pool: &sqlx::PgPool,
    col: &str,
    tables: &[&str],
) -> i64 {
    for table in tables {
        let q = format!("SELECT COUNT(DISTINCT \"{}\") FROM \"{}\"", col, table);
        if let Ok(row) = sqlx::query_scalar::<_, i64>(&q).fetch_one(pool).await {
            return row;
        }
    }
    0
}

fn format_uptime(secs: u64) -> String {
    let d = secs / 86400;
    let h = (secs % 86400) / 3600;
    let m = (secs % 3600) / 60;
    let s = secs % 60;
    if d > 0 {
        format!("{d}d {h}h {m}m")
    } else if h > 0 {
        format!("{h}h {m}m {s}s")
    } else {
        format!("{m}m {s}s")
    }
}
