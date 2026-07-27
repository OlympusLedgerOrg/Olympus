use std::time::Duration;

use env_logger::Env;
use futures::stream::StreamExt;
use serial_test::file_serial;
use tempfile::TempDir;
use tokio::sync::Mutex;

use pg_embed::pg_access::PgAccess;
use pg_embed::pg_enums::{PgAuthMethod, PgServerStatus};
use pg_embed::pg_errors::{Error, Result};
use pg_embed::pg_fetch::{PG_V15, PgFetchSettings};
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
    } // drop exact-terminates the retained child, then removes db_path
    assert!(!PgAccess::pg_version_file_exists(&db_path).await?);
    Ok(())
}

#[tokio::test]
#[file_serial(pg_port_5432)]
#[file_serial(pg_port_5434)]
async fn multiple_concurrent() -> Result<()> {
    // TempDirs declared before pgs so they outlive PgEmbed instances
    let dir1 = TempDir::new().map_err(|e| Error::DirCreationError(e.to_string()))?;
    let dir2 = TempDir::new().map_err(|e| Error::DirCreationError(e.to_string()))?;

    // Exercise concurrent warm-cache verification and the process-local and
    // cross-process cache leases. Cold-cache atomic publication has focused
    // coverage in pg_access's staging tests.
    let (pg1, pg2) = tokio::join!(
        setup_with_timeout(5432, dir1.path().join("db"), Duration::from_secs(60)),
        setup_with_timeout(5434, dir2.path().join("db"), Duration::from_secs(60))
    );
    let pg1 = pg1?;
    let pg2 = pg2?;
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
        version: PG_V15,
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
        version: PG_V15,
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
        version: PG_V15,
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

/// Verify that a deterministically disconnected Maven host produces
/// `Error::DownloadFailure`.
#[tokio::test]
async fn download_failure() -> Result<()> {
    let (host, server) = disconnecting_mock_server().await;
    let fetch_settings = PgFetchSettings {
        // Exercise the network path directly so an existing verified binary
        // cache cannot turn this into a warm-start test.
        host,
        version: PG_V15,
        ..Default::default()
    };
    let result = fetch_settings.fetch_postgres().await;
    server.await.unwrap();
    assert!(matches!(result, Err(Error::DownloadFailure(_))));
    Ok(())
}

/// Verify that `PgEmbed::setup()` drives the streamed acquisition path and
/// leaves no archive or verification marker after a network failure.
#[tokio::test]
async fn setup_download_failure_does_not_create_verified_cache() -> Result<()> {
    let dir = TempDir::new().map_err(|e| Error::DirCreationError(e.to_string()))?;
    let (host, server) = disconnecting_mock_server().await;
    let fetch_settings = PgFetchSettings {
        host,
        version: PG_V15,
        ..Default::default()
    };
    let platform = fetch_settings.platform();
    let pg_settings = PgSettings {
        database_dir: dir.path().join("db"),
        port: 5432,
        user: "postgres".to_string(),
        password: "password".to_string(),
        auth_method: PgAuthMethod::MD5,
        persistent: true,
        timeout: Some(Duration::from_secs(5)),
        migration_dir: None,
    };
    let mut pg = PgEmbed::new(pg_settings, fetch_settings).await?;

    // Route this test through an isolated empty cache so a valid machine cache
    // cannot turn setup into a warm start.
    let cache_dir = dir.path().join("cache");
    pg.pg_access.cache_dir = cache_dir.clone();
    pg.pg_access.init_db_exe = cache_dir.join(if cfg!(windows) {
        "bin/initdb.exe"
    } else {
        "bin/initdb"
    });
    pg.pg_access.pg_ctl_exe = cache_dir.join(if cfg!(windows) {
        "bin/pg_ctl.exe"
    } else {
        "bin/pg_ctl"
    });
    pg.pg_access.zip_file_path = cache_dir.join(format!("{platform}-{}.zip", PG_V15.0));

    let partial_path = pg.pg_access.zip_file_path.with_extension("zip.partial");
    let result = pg.setup().await;
    server.await.unwrap();

    assert!(matches!(result, Err(Error::DownloadFailure(_))));
    assert!(!partial_path.exists());
    assert!(!pg.pg_access.zip_file_path.exists());
    assert!(!cache_dir.join(".olympus-verified-package.sha256").exists());
    Ok(())
}

async fn disconnecting_mock_server() -> (String, tokio::task::JoinHandle<()>) {
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
        .await
        .unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        drop(stream);
    });
    (format!("http://{address}"), server)
}
