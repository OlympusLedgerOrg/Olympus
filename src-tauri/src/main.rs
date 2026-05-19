#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod api;
mod db;
mod integrity;
mod routes;
mod server;
mod state;

use tauri::Manager;

struct ApiState {
    port: u16,
}

#[tauri::command]
fn get_api_port(state: tauri::State<ApiState>) -> u16 {
    state.port
}

fn main() {
    tauri::Builder::default()
        .setup(|app| {
            // Resolve app data dir before moving into the thread.
            let app_data_dir = app
                .path()
                .app_data_dir()
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::NotFound, e.to_string()))?;

            let (tx, rx) = std::sync::mpsc::channel();
            std::thread::spawn(move || {
                tokio::runtime::Runtime::new()
                    .expect("tokio runtime")
                    .block_on(async move {
                        // Use embedded PG unless DATABASE_URL is set explicitly (dev/CI).
                        let pool = if let Ok(url) = std::env::var("DATABASE_URL") {
                            db::connect_external(&url).await
                        } else {
                            match db::init_embedded(&app_data_dir).await {
                                Ok(embedded) => {
                                    // Keep EmbeddedDb alive for the process lifetime.
                                    let pool = embedded.pool.clone();
                                    std::mem::forget(embedded);
                                    Some(pool)
                                }
                                Err(e) => {
                                    eprintln!(
                                        "[olympus-desktop] embedded PG failed: {e} \
                                         — DB-backed routes will return 503"
                                    );
                                    None
                                }
                            }
                        };

                        let app_state = state::AppState::new(pool);
                        let addr = server::start(app_state)
                            .await
                            .expect("axum server failed to bind");
                        tx.send(addr.port()).expect("receiver dropped before port was sent");
                        std::future::pending::<()>().await;
                    });
            });
            let port = rx
                .recv_timeout(std::time::Duration::from_secs(30))
                .map_err(|e| std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    format!("axum server failed to report port within 30s: {e}"),
                ))?;
            app.manage(ApiState { port });
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![get_api_port])
        .run(tauri::generate_context!())
        .expect("failed to start Olympus desktop");
}
