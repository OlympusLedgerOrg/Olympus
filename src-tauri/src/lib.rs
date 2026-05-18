pub mod api;
pub mod db;
pub mod integrity;
pub mod zk;

use std::net::SocketAddr;
use std::sync::OnceLock;

use tauri::Manager;
use tokio::net::TcpListener;

static API_PORT: OnceLock<u16> = OnceLock::new();

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_shell::init())
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_fs::init())
        .plugin(tauri_plugin_notification::init())
        .setup(|app| {
            let app_handle = app.handle().clone();

            #[cfg(feature = "embedded-db")]
            let data_dir = app.path().app_data_dir().expect("no app data dir");

            tauri::async_runtime::spawn(async move {
                #[cfg(feature = "embedded-db")]
                let pool_result = {
                    let (pg, pool) = db::embedded::start(data_dir).await
                        .expect("embedded postgres failed to start");
                    // Keep the PgEmbed handle alive for the process lifetime.
                    std::mem::forget(pg);
                    Ok::<_, anyhow::Error>(pool)
                };

                #[cfg(not(feature = "embedded-db"))]
                let pool_result = db::connect_external().await;

                match pool_result {
                    Ok(pool) => {
                        match start_api(pool).await {
                            Ok(port) => {
                                API_PORT.set(port).ok();
                                std::env::set_var("OLYMPUS_API_PORT", port.to_string());
                                let _ = app_handle.emit("api-ready", port);
                                if let Some(splash) = app_handle.get_webview_window("splashscreen") {
                                    let _ = splash.close();
                                }
                                if let Some(main) = app_handle.get_webview_window("main") {
                                    let _ = main.show();
                                }
                                tracing::info!(port, "Olympus API ready");
                            }
                            Err(e) => tracing::error!(err = %e, "API server failed"),
                        }
                    }
                    Err(e) => tracing::error!(err = %e, "Database failed to start"),
                }
            });

            // Launch the Go sequencer sidecar when opted in.
            if std::env::var("OLYMPUS_USE_GO_SEQUENCER").as_deref() == Ok("true") {
                use tauri_plugin_shell::ShellExt;
                let sidecar = app.shell().sidecar("sequencer-go");
                match sidecar {
                    Ok(cmd) => {
                        let _ = cmd.spawn();
                        tracing::info!("Go sequencer sidecar started");
                    }
                    Err(e) => tracing::warn!(err = %e, "Go sequencer sidecar not found"),
                }
            }

            #[cfg(debug_assertions)]
            if let Some(window) = app.get_webview_window("main") {
                window.open_devtools();
            }

            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            integrity::batch::verify_batch_parallel,
            zk::commands::verify_proof,
            get_api_port,
        ])
        .run(tauri::generate_context!())
        .expect("error running Olympus");
}

async fn start_api(pool: sqlx::PgPool) -> anyhow::Result<u16> {
    let state = api::state::AppState::new(pool);
    let router = api::router(state);
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let port = listener.local_addr()?.port();
    axum::serve(
        listener,
        router.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await?;
    Ok(port)
}

#[tauri::command]
fn get_api_port() -> Option<u16> {
    API_PORT.get().copied()
}
