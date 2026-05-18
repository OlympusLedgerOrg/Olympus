use anyhow::{Context, Result};
use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;
use std::path::PathBuf;

/// Run all pending sqlx migrations against `pool`.
/// `migrations/` lives one level above `src-tauri/`, so the macro path is `../migrations`.
pub async fn run_migrations(pool: &PgPool) -> Result<()> {
    sqlx::migrate!("../migrations")
        .run(pool)
        .await
        .context("sqlx migrations failed")
}

// ── Embedded PostgreSQL (feature = "embedded-db") ─────────────────────────────

#[cfg(feature = "embedded-db")]
pub mod embedded {
    use super::*;
    use pg_embed::pg_enums::PgAuthMethod;
    use pg_embed::pg_fetch::{PgFetchSettings, PG_V15};
    use pg_embed::postgres::{PgEmbed, PgSettings};

    const PG_PORT: u16 = 5433;
    const PG_USER: &str = "olympus";
    const PG_DB: &str = "olympus";
    // Embedded DB is localhost-only; this is not a production secret.
    const PG_PASSWORD: &str = "olympus_local";

    pub fn connection_url() -> String {
        format!("postgres://{PG_USER}:{PG_PASSWORD}@localhost:{PG_PORT}/{PG_DB}")
    }

    /// Start an embedded PostgreSQL instance in `data_dir`.
    /// Downloads PG binaries on first run (~50 MB), then starts the cluster.
    /// The returned `PgEmbed` must stay alive for the process lifetime.
    pub async fn start(data_dir: PathBuf) -> Result<(PgEmbed, PgPool)> {
        let pg_dir = data_dir.join("postgres");
        std::fs::create_dir_all(&pg_dir)
            .context("failed to create postgres data directory")?;

        let settings = PgSettings {
            database_dir: pg_dir,
            port: PG_PORT,
            user: PG_USER.into(),
            password: PG_PASSWORD.into(),
            auth_method: PgAuthMethod::Plain,
            persistent: true,
            timeout: Some(std::time::Duration::from_secs(30)),
            migration_dir: None,
        };

        // pg-embed 0.7 does not yet ship a PG16 constant — `PG_V15` is the
        // latest available. Bumping pg-embed (>0.7) is a separate concern.
        let fetch = PgFetchSettings {
            version: PG_V15,
            ..Default::default()
        };

        let mut pg = PgEmbed::new(settings, fetch).await?;
        pg.setup().await?;
        pg.start_db().await?;
        pg.create_database(PG_DB).await.ok(); // ignore "already exists"

        let pool = PgPoolOptions::new()
            .max_connections(20)
            .connect(&connection_url())
            .await
            .context("failed to connect to embedded postgres")?;

        super::run_migrations(&pool).await?;

        tracing::info!(port = PG_PORT, "Embedded PostgreSQL ready");
        Ok((pg, pool))
    }
}

// ── External PostgreSQL (feature not enabled — dev/CI mode) ──────────────────

#[cfg(not(feature = "embedded-db"))]
pub async fn connect_external() -> Result<PgPool> {
    let url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://olympus@localhost:5432/olympus".into());
    let pool = PgPoolOptions::new()
        .max_connections(20)
        .connect(&url)
        .await
        .context("failed to connect to postgres")?;
    run_migrations(&pool).await?;
    Ok(pool)
}
