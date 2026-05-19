use sqlx::PgPool;

/// Create a PostgreSQL connection pool from `database_url`.
/// Returns `None` (with a logged warning) when the URL is absent or the
/// connection fails, so the server still starts in environments without a DB.
pub async fn create_pool(database_url: Option<&str>) -> Option<PgPool> {
    let url = match database_url {
        Some(u) if !u.is_empty() => u,
        _ => {
            eprintln!("[olympus-desktop] DATABASE_URL not set — DB-backed routes will return 503");
            return None;
        }
    };
    match PgPool::connect(url).await {
        Ok(pool) => Some(pool),
        Err(e) => {
            eprintln!("[olympus-desktop] DB connection failed: {e} — DB-backed routes will return 503");
            None
        }
    }
}
