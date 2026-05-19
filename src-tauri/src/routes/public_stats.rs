use axum::{extract::State, http::StatusCode, response::Json};
use serde::Serialize;
use sqlx::PgPool;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::state::{AppState, Cached};

const CACHE_TTL: Duration = Duration::from_secs(10);

#[derive(Serialize, Clone)]
pub struct PublicStats {
    pub nodes: i64,
    pub shards: i64,
    pub proofs: i64,
    pub sbts_issued: i64,
    pub uptime: String,
    pub uptime_seconds: i64,
    pub copies: i64,
}

pub async fn get_public_stats(
    State(state): State<AppState>,
) -> Result<Json<PublicStats>, StatusCode> {
    {
        let cache = state.stats_cache.lock().await;
        if let Some(c) = &*cache {
            if c.stored_at.elapsed() < CACHE_TTL {
                return Ok(Json(c.value.clone()));
            }
        }
    }

    let pool = state.pool.as_ref().ok_or(StatusCode::SERVICE_UNAVAILABLE)?;

    let (nodes, sbts_issued, shards, proofs) = tokio::try_join!(
        async { Ok::<_, StatusCode>(count_nodes(pool).await) },
        async { Ok::<_, StatusCode>(count_issued_sbts(pool).await) },
        async { Ok::<_, StatusCode>(count_distinct_shards(pool).await) },
        async { Ok::<_, StatusCode>(count_public_proofs(pool).await) },
    )?;

    let now_unix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;
    let uptime_seconds = (now_unix - state.started_unix).max(0);

    let stats = PublicStats {
        nodes,
        shards,
        proofs,
        sbts_issued,
        uptime: format_uptime(uptime_seconds as u64),
        uptime_seconds,
        copies: nodes,
    };

    *state.stats_cache.lock().await = Some(Cached {
        value: stats.clone(),
        stored_at: std::time::Instant::now(),
    });
    Ok(Json(stats))
}

// ─── helpers ─────────────────────────────────────────────────────────────────

async fn column_exists(pool: &PgPool, table: &str, col: &str) -> bool {
    sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS(SELECT 1 FROM information_schema.columns \
         WHERE table_schema = 'public' AND table_name = $1 AND column_name = $2)",
    )
    .bind(table)
    .bind(col)
    .fetch_one(pool)
    .await
    .unwrap_or(false)
}

async fn count_nodes(pool: &PgPool) -> i64 {
    let node_operators = count_node_operators(pool).await;
    let witness_origins = count_witness_origins(pool).await;
    node_operators + witness_origins
}

async fn count_node_operators(pool: &PgPool) -> i64 {
    if !column_exists(pool, "operators", "role").await {
        return 0;
    }
    if column_exists(pool, "operators", "revoked_at").await {
        sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM operators WHERE role = 'node_operator' AND revoked_at IS NULL",
        )
    } else {
        sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM operators WHERE role = 'node_operator'",
        )
    }
    .fetch_one(pool)
    .await
    .unwrap_or(0)
}

async fn count_witness_origins(pool: &PgPool) -> i64 {
    if !column_exists(pool, "witness_observations", "origin").await {
        return 0;
    }
    sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(DISTINCT origin) FROM witness_observations",
    )
    .fetch_one(pool)
    .await
    .unwrap_or(0)
}

async fn count_issued_sbts(pool: &PgPool) -> i64 {
    let has_revoked = column_exists(pool, "key_credentials", "revoked_at").await;
    let has_sbt = column_exists(pool, "key_credentials", "sbt_nontransferable").await;

    // If neither column exists, the table itself may not exist — return 0.
    if !has_revoked && !has_sbt {
        let table_exists = column_exists(pool, "key_credentials", "id").await
            || sqlx::query_scalar::<_, bool>(
                "SELECT EXISTS(SELECT 1 FROM information_schema.tables \
                 WHERE table_schema = 'public' AND table_name = 'key_credentials')",
            )
            .fetch_one(pool)
            .await
            .unwrap_or(false);
        if !table_exists {
            return 0;
        }
    }

    let query = match (has_revoked, has_sbt) {
        (true, true) => "SELECT COUNT(*) FROM key_credentials \
                         WHERE revoked_at IS NULL AND sbt_nontransferable = true",
        (true, false) => "SELECT COUNT(*) FROM key_credentials WHERE revoked_at IS NULL",
        (false, true) => "SELECT COUNT(*) FROM key_credentials WHERE sbt_nontransferable = true",
        (false, false) => "SELECT COUNT(*) FROM key_credentials",
    };
    sqlx::query_scalar::<_, i64>(query)
        .fetch_one(pool)
        .await
        .unwrap_or(0)
}

async fn count_distinct_shards(pool: &PgPool) -> i64 {
    // Collect distinct shard_id values across all relevant tables via a UNION.
    // Each branch is guarded by an information_schema existence check so the
    // query degrades gracefully when tables don't exist yet.
    let tables = [
        "ingestion_proofs",
        "doc_commits",
        "dataset_artifacts",
        "dataset_lineage_events",
    ];
    let mut parts: Vec<&str> = Vec::new();
    for t in &tables {
        if column_exists(pool, t, "shard_id").await {
            parts.push(t);
        }
    }
    if parts.is_empty() {
        return 0;
    }
    // Build a safe UNION query — table names are validated against the
    // compile-time allowlist above, never from user input.
    let union_sql = parts
        .iter()
        .map(|t| format!("SELECT shard_id FROM \"{}\" WHERE shard_id IS NOT NULL", t))
        .collect::<Vec<_>>()
        .join(" UNION ");
    let sql = format!("SELECT COUNT(*) FROM ({}) AS _shards", union_sql);
    sqlx::query_scalar::<_, i64>(&sql)
        .fetch_one(pool)
        .await
        .unwrap_or(0)
}

async fn count_public_proofs(pool: &PgPool) -> i64 {
    let mut total: i64 = 0;

    // ingestion_proofs: count all rows
    let ingestion_exists: bool = sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS(SELECT 1 FROM information_schema.tables \
         WHERE table_schema = 'public' AND table_name = 'ingestion_proofs')",
    )
    .fetch_one(pool)
    .await
    .unwrap_or(false);
    if ingestion_exists {
        total += sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM ingestion_proofs")
            .fetch_one(pool)
            .await
            .unwrap_or(0);
    }

    // Non-empty proof columns in other tables
    for (table, col) in [
        ("doc_commits", "zk_proof"),
        ("dataset_artifacts", "zk_proof"),
        ("credential_ledger_events", "inclusion_proof"),
    ] {
        if column_exists(pool, table, col).await {
            let sql = format!(
                "SELECT COUNT(*) FROM \"{}\" WHERE {} IS NOT NULL AND {} != ''",
                table, col, col
            );
            total += sqlx::query_scalar::<_, i64>(&sql)
                .fetch_one(pool)
                .await
                .unwrap_or(0);
        }
    }
    total
}

pub fn format_uptime(seconds: u64) -> String {
    if seconds < 60 {
        format!("{}s", seconds)
    } else if seconds < 3600 {
        format!("{}m", seconds / 60)
    } else if seconds < 86400 {
        format!("{}h", seconds / 3600)
    } else {
        format!("{}d", seconds / 86400)
    }
}

// ─── tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_uptime_seconds() {
        assert_eq!(format_uptime(0), "0s");
        assert_eq!(format_uptime(59), "59s");
    }

    #[test]
    fn format_uptime_minutes() {
        assert_eq!(format_uptime(60), "1m");
        assert_eq!(format_uptime(3599), "59m");
    }

    #[test]
    fn format_uptime_hours() {
        assert_eq!(format_uptime(3600), "1h");
        assert_eq!(format_uptime(86399), "23h");
    }

    #[test]
    fn format_uptime_days() {
        assert_eq!(format_uptime(86400), "1d");
        assert_eq!(format_uptime(172800), "2d");
    }
}
