#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod api;
mod db;
mod integrity;
mod routes;
mod server;
mod state;
mod zk;

use tauri::Manager;

struct ApiState {
    port: u16,
}

#[tauri::command]
fn get_api_port(state: tauri::State<ApiState>) -> u16 {
    state.port
}

struct DbErrorState {
    error: Option<String>,
}

#[tauri::command]
fn get_db_error(state: tauri::State<DbErrorState>) -> Option<String> {
    state.error.clone()
}

fn main() {
    tauri::Builder::default()
        .setup(|app| {
            // Resolve app data dir before moving into the thread.
            let app_data_dir = app
                .path()
                .app_data_dir()
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::NotFound, e.to_string()))?;

            let (tx, rx) = std::sync::mpsc::channel::<(u16, Option<String>)>();
            std::thread::spawn(move || {
                tokio::runtime::Runtime::new()
                    .expect("tokio runtime")
                    .block_on(async move {
                        // Use embedded PG unless DATABASE_URL is set explicitly (dev/CI).
                        let (pool, db_error) = if let Ok(url) = std::env::var("DATABASE_URL") {
                            let p = db::connect_external(&url).await;
                            let err = if p.is_none() {
                                Some(format!(
                                    "Could not connect to external database.\n\
                                     URL: {url}\n\
                                     Check that the server is running and DATABASE_URL is correct."
                                ))
                            } else {
                                None
                            };
                            (p, err)
                        } else {
                            match db::init_embedded(&app_data_dir).await {
                                Ok(embedded) => {
                                    // Keep EmbeddedDb alive for the process lifetime.
                                    let pool = embedded.pool.clone();
                                    std::mem::forget(embedded);
                                    (Some(pool), None)
                                }
                                Err(e) => {
                                    let msg = format!(
                                        "Embedded PostgreSQL failed to start.\n\
                                         Error: {e}\n\
                                         Data dir: {}\n\
                                         Hint: check that port 5433 is free and disk has space.",
                                        app_data_dir.display()
                                    );
                                    eprintln!("[olympus-desktop] {msg}");
                                    (None, Some(msg))
                                }
                            }
                        };

                        let app_state = state::AppState::new_with_error(pool, db_error.clone());
                        let addr = server::start(app_state)
                            .await
                            .expect("axum server failed to bind");
                        tx.send((addr.port(), db_error))
                            .expect("receiver dropped before port was sent");
                        std::future::pending::<()>().await;
                    });
            });

            let (port, db_error) = rx
                .recv_timeout(std::time::Duration::from_secs(30))
                .map_err(|e| std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    format!("axum server failed to report port within 30s: {e}"),
                ))?;

            app.manage(ApiState { port });
            app.manage(DbErrorState { error: db_error });
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![get_api_port, get_db_error])
        .run(tauri::generate_context!())
        .expect("failed to start Olympus desktop");
}
