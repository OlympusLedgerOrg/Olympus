use std::time::Duration;

use env_logger::Env;
use futures::stream::StreamExt;
use serial_test::file_serial;
use tempfile::TempDir;
use tokio::sync::Mutex;

use pg_embed::pg_access::PgAccess;
use pg_embed::pg_enums::{PgAuthMethod, PgServerStatus};
use pg_embed::pg_errors::{Error, Result};
use pg_embed::pg_fetch::{PG_V17, PgFetchSettings, PostgresVersion};
use pg_embed::postgres::{PgEmbed, PgSettings};

#[path = "common.rs"]
mod common;

#[tokio::test]
#[file_serial(pg_port_5432)]
async fn start_stop() -> Result<()> {
    let (_dir, mut pg) = common::setup_with_tempdir(5432, false, None).await?;
    {
        let server_status = *pg.server_status.lock().await;
        assert_eq!(server_status, PgServerStatus::Initialized);
    }

    pg.start_db().await?;
    {
        let server_status = *pg.server_status.lock().await;
        assert_eq!(server_status, PgServerStatus::Started);
    }

    pg.stop_db().await?;
    {
        let server_status = *pg.server_status.lock().await;
        assert_eq!(server_status, PgServerStatus::Stopped);
    }

    Ok(())
}

#[tokio::test]
#[file_serial(pg_port_5432)]
async fn server_drop() -> Result<()> {
    // dir declared before the inner scope so it outlives pg
    let dir = TempDir::new().map_err(|e| Error::DirCreationError(e.to_string()))?;
    let db_path = dir.path().join("db");
    {
        let mut pg = common::setup(5432, db_path.clone(), false, None).await?;
        pg.start_db().await?;
        assert!(PgAccess::pg_version_file_exists(&db_path).await?);
    } // pg drops here: stop_db_sync + clean() remove db_path
    assert!(!PgAccess::pg_version_file_exists(&db_path).await?);
    Ok(())
}

#[tokio::test]
#[file_serial(pg_port_5432)]
#[file_serial(pg_port_5434)]
async fn multiple_concurrent() -> Result<()> {
    PgAccess::purge().await?;

    // TempDirs declared before pgs so they outlive PgEmbed instances
    let dir1 = TempDir::new().map_err(|e| Error::DirCreationError(e.to_string()))?;
    let dir2 = TempDir::new().map_err(|e| Error::DirCreationError(e.to_string()))?;

    // The two setup() calls used to run via futures::join_all, which races the
    // shared `~/.cache/pg-embed` directory: one task downloads + unpacks the
    // postgres binaries while the other simultaneously checks the cache,
    // sometimes seeing a half-extracted state. On CI that race plus the
    // 10-second default per-command timeout produced the well-known
    // "single-user server is running" wedge in stop_db. Serialise the setup
    // phase — it's idempotent, fast on a warm cache, and runs once total —
    // and keep the start/stop calls concurrent so this test still actually
    // exercises cross-port concurrency (which is its name and intent).
    //
    // Per-test timeout is bumped to 60 s (vs common::setup's 10 s default)
    // because two PgEmbed instances share CPU on the same runner during the
    // concurrent start/stop phases, and the GitHub Actions ubuntu-latest
    // runners are CPU-shared.
    let pg1 = setup_with_timeout(5432, dir1.path().join("db"), Duration::from_secs(60)).await?;
    let pg2 = setup_with_timeout(5434, dir2.path().join("db"), Duration::from_secs(60)).await?;
    let pgs: Vec<Mutex<PgEmbed>> = vec![Mutex::new(pg1), Mutex::new(pg2)];

    futures::stream::iter(&pgs)
        .for_each_concurrent(None, |pg| async move {
            let mut pg = pg.lock().await;
            pg.start_db().await.expect("start_db failed");
            {
                let server_status = *pg.server_status.lock().await;
                assert_eq!(server_status, PgServerStatus::Started);
            }
        })
        .await;

    futures::stream::iter(&pgs)
        .for_each_concurrent(None, |pg| async move {
            let mut pg = pg.lock().await;
            pg.stop_db().await.expect("stop_db failed");
            {
                let server_status = *pg.server_status.lock().await;
                assert_eq!(server_status, PgServerStatus::Stopped);
            }
        })
        .await;

    Ok(())
}

/// Local `setup` variant for `multiple_concurrent` that takes an explicit
/// timeout. `common::setup` hardcodes 10 s, which is too tight when two
/// instances share the runner's CPU during the concurrent start/stop phases.
async fn setup_with_timeout(
    port: u16,
    database_dir: std::path::PathBuf,
    timeout: Duration,
) -> Result<PgEmbed> {
    let _ = env_logger::Builder::from_env(Env::default().default_filter_or("info"))
        .is_test(true)
        .try_init();
    let pg_settings = PgSettings {
        database_dir,
        port,
        user: "postgres".to_string(),
        password: "password".to_string(),
        auth_method: PgAuthMethod::MD5,
        persistent: false,
        timeout: Some(timeout),
        migration_dir: None,
    };
    let fetch_settings = PgFetchSettings {
        version: PG_V17,
        ..Default::default()
    };
    let mut pg = PgEmbed::new(pg_settings, fetch_settings).await?;
    pg.setup().await?;
    Ok(pg)
}

#[tokio::test]
#[file_serial(pg_port_5432)]
async fn persistent_true() -> Result<()> {
    let (_dir, pg) = common::setup_with_tempdir(5432, true, None).await?;
    let database_dir = pg.pg_access.database_dir.clone();
    let pw_file_path = pg.pg_access.pw_file_path.clone();

    assert!(PgAccess::pg_version_file_exists(&database_dir).await?);

    drop(pg); // persistent=true: no cleanup on drop

    assert!(PgAccess::pg_version_file_exists(&database_dir).await?);

    PgAccess::clean_up(database_dir.clone(), pw_file_path).await?;

    assert!(!PgAccess::pg_version_file_exists(&database_dir).await?);

    Ok(())
}

#[tokio::test]
#[file_serial(pg_port_5432)]
async fn persistent_false() -> Result<()> {
    // dir declared before inner scope so it outlives _pg
    let dir = TempDir::new().map_err(|e| Error::DirCreationError(e.to_string()))?;
    let db_path = dir.path().join("db");
    {
        let _pg = common::setup(5432, db_path.clone(), false, None).await?;
        assert!(PgAccess::pg_version_file_exists(&db_path).await?);
    } // _pg drops: clean() removes db_path
    assert!(!PgAccess::pg_version_file_exists(&db_path).await?);

    Ok(())
}

/// Verify that a persistent cluster is reused by a second `PgEmbed` on the same
/// directory: `setup()` detects the existing `PG_VERSION` file and skips
/// `initdb`.
#[tokio::test]
#[file_serial(pg_port_5432)]
async fn cluster_reuse() -> Result<()> {
    let dir = TempDir::new().map_err(|e| Error::DirCreationError(e.to_string()))?;
    let db_path = dir.path().join("db");

    // First lifecycle — create and start with persistent=true
    {
        let mut pg = common::setup(5432, db_path.clone(), true, None).await?;
        pg.start_db().await?;
        pg.stop_db().await?;
    } // drop: persistent=true, so no cleanup

    // Cluster files survive the drop
    assert!(PgAccess::pg_version_file_exists(&db_path).await?);

    // Second lifecycle — reuse the existing cluster
    {
        let mut pg = common::setup(5432, db_path.clone(), true, None).await?;
        // setup() should have detected the existing cluster and set Initialized
        {
            let server_status = *pg.server_status.lock().await;
            assert_eq!(server_status, PgServerStatus::Initialized);
        }
        pg.start_db().await?;
        {
            let server_status = *pg.server_status.lock().await;
            assert_eq!(server_status, PgServerStatus::Started);
        }
        pg.stop_db().await?;
        // Manual cleanup since persistent=true
        PgAccess::clean_up(db_path.clone(), pg.pg_access.pw_file_path.clone()).await?;
    }

    assert!(!PgAccess::pg_version_file_exists(&db_path).await?);
    Ok(())
}

#[tokio::test]
#[file_serial(pg_port_5432)]
async fn server_timeout() -> Result<()> {
    let dir = TempDir::new().map_err(|e| Error::DirCreationError(e.to_string()))?;
    let _ = env_logger::Builder::from_env(Env::default().default_filter_or("info"))
        .is_test(true)
        .try_init();
    let pg_settings = PgSettings {
        database_dir: dir.path().join("db"),
        port: 5432,
        user: "postgres".to_string(),
        password: "password".to_string(),
        auth_method: PgAuthMethod::MD5,
        persistent: false,
        // 60 s for the initial setup/initdb (vs the old 10 s): under the full
        // workspace pre-push run this initdb is CPU-starved and was timing out
        // here at `pg.setup().await?` before the test could exercise the
        // deliberate sub-second timeout below. The actual timeout assertion
        // re-sets the deadline to 10 ms after setup, so this only hardens the
        // setup phase.
        timeout: Some(Duration::from_secs(60)),
        migration_dir: None,
    };
    let fetch_settings = PgFetchSettings {
        version: PG_V17,
        ..Default::default()
    };
    let mut pg = PgEmbed::new(pg_settings, fetch_settings).await?;
    pg.setup().await?;
    // Deliberately tiny deadline to prove start_db surfaces PgTimedOutError.
    pg.pg_settings.timeout = Some(Duration::from_millis(10));
    let res = pg.start_db().await.err();
    assert_eq!(Some(Error::PgTimedOutError), res);

    Ok(())
}

/// Verify that `timeout: None` allows the server to start without an enforced
/// deadline.
#[tokio::test]
#[file_serial(pg_port_5432)]
async fn timeout_none() -> Result<()> {
    let dir = TempDir::new().map_err(|e| Error::DirCreationError(e.to_string()))?;
    let pg_settings = PgSettings {
        database_dir: dir.path().join("db"),
        port: 5432,
        user: "postgres".to_string(),
        password: "password".to_string(),
        auth_method: PgAuthMethod::MD5,
        persistent: false,
        timeout: None,
        migration_dir: None,
    };
    let fetch_settings = PgFetchSettings {
        version: PG_V17,
        ..Default::default()
    };
    let mut pg = PgEmbed::new(pg_settings, fetch_settings).await?;
    pg.setup().await?;
    pg.start_db().await?;
    {
        let server_status = *pg.server_status.lock().await;
        assert_eq!(server_status, PgServerStatus::Started);
    }
    pg.stop_db().await?;
    Ok(())
}

/// Verify that an unreachable Maven host produces `Error::DownloadFailure`.
#[tokio::test]
async fn download_failure() -> Result<()> {
    let dir = TempDir::new().map_err(|e| Error::DirCreationError(e.to_string()))?;
    let fetch_settings = PgFetchSettings {
        // Port 19999 is almost certainly not listening; use a non-existent version
        // so cached binaries are never found.
        host: "http://127.0.0.1:19999".to_string(),
        version: PostgresVersion("99.0.0"),
        ..Default::default()
    };
    let pg_settings = PgSettings {
        database_dir: dir.path().join("db"),
        port: 5499,
        user: "postgres".to_string(),
        password: "password".to_string(),
        auth_method: PgAuthMethod::MD5,
        persistent: false,
        timeout: Some(Duration::from_secs(10)),
        migration_dir: None,
    };
    let mut pg = PgEmbed::new(pg_settings, fetch_settings).await?;
    let result = pg.setup().await;
    assert!(matches!(result, Err(Error::DownloadFailure(_))));
    Ok(())
}
