#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]
// Match lib.rs: the bin re-includes the same module tree, so without this
// every item not reachable from `main` is reported as dead code.
#![allow(dead_code, unused_imports)]

mod api;
mod bootstrap;
mod db;
mod integrity;
mod merkle;
mod routes;
mod server;
mod state;
mod zk;
#[cfg(feature = "federation")]
mod federation;

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

/// Proxy a file commit through Tauri IPC so the webview avoids cross-origin /
/// mixed-content restrictions.  The frontend sends the file bytes + metadata;
/// we POST them to the local Axum server from the native side.
#[tauri::command]
#[allow(clippy::too_many_arguments)]
async fn commit_file(
    api_state: tauri::State<'_, ApiState>,
    api_key: String,
    file_bytes: Vec<u8>,
    file_name: String,
    shard_id: String,
    record_id: String,
    version: u32,
    original_hash: Option<String>,
) -> Result<serde_json::Value, String> {
    let port = api_state.port;
    let url = format!("http://127.0.0.1:{port}/ingest/files");

    let file_part = reqwest::multipart::Part::bytes(file_bytes)
        .file_name(file_name)
        .mime_str("application/octet-stream")
        .map_err(|e| e.to_string())?;

    let mut form = reqwest::multipart::Form::new()
        .part("file", file_part)
        .text("shard_id", shard_id)
        .text("record_id", record_id)
        .text("version", version.to_string());

    if let Some(oh) = original_hash {
        if !oh.is_empty() {
            form = form.text("original_hash", oh);
        }
    }

    let resp = reqwest::Client::new()
        .post(&url)
        .header("X-API-Key", &api_key)
        .multipart(form)
        .send()
        .await
        .map_err(|e| format!("Request failed: {e}"))?;

    let status = resp.status().as_u16();
    let body: serde_json::Value = resp
        .json()
        .await
        .map_err(|e| format!("Response parse error: {e}"))?;

    if status >= 400 {
        let detail = body.get("detail")
            .and_then(|v| v.as_str())
            .unwrap_or("Unknown error");
        return Err(format!("HTTP {status}: {detail}"));
    }

    Ok(body)
}

/// Holds the embedded PG instance so it can be stopped cleanly on exit.
/// Wrapped in Mutex so the on-exit handler can take ownership.
struct EmbeddedDbState {
    inner: std::sync::Mutex<Option<db::EmbeddedDb>>,
}

fn main() {
    tauri::Builder::default()
        .setup(|app| {
            let app_data_dir = app
                .path()
                .app_data_dir()
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::NotFound, e.to_string()))?;

            let (tx, rx) = std::sync::mpsc::channel::<(u16, Option<String>, Option<db::EmbeddedDb>)>();
            std::thread::spawn(move || {
                tokio::runtime::Runtime::new()
                    .expect("tokio runtime")
                    .block_on(async move {
                        let (pool, db_error, embedded) = if let Ok(url) = std::env::var("DATABASE_URL") {
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
                            (p, err, None)
                        } else {
                            match db::init_embedded(&app_data_dir).await {
                                Ok(embedded) => {
                                    let pool = embedded.pool.clone();
                                    (Some(pool), None, Some(embedded))
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
                                    (None, Some(msg), None)
                                }
                            }
                        };

                        // Bootstrap: ensure system user, API key, BJJ authority, and SBT exist.
                        let bjj_result = if let Some(ref p) = pool {
                            bootstrap::run(p).await
                        } else {
                            None
                        };

                        let mut app_state = state::AppState::new_with_error(pool, db_error.clone());
                        if let Some(br) = bjj_result {
                            app_state.bjj_authority_key = Some(br.bjj_authority_key);
                            app_state.bjj_authority_pubkey = Some(br.bjj_authority_pubkey);
                        }
                        let addr = server::start(app_state)
                            .await
                            .expect("axum server failed to bind");
                        tx.send((addr.port(), db_error, embedded))
                            .expect("receiver dropped before port was sent");
                        std::future::pending::<()>().await;
                    });
            });

            let (port, db_error, embedded) = rx
                .recv_timeout(std::time::Duration::from_secs(30))
                .map_err(|e| std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    format!("axum server failed to report port within 30s: {e}"),
                ))?;

            app.manage(ApiState { port });
            app.manage(DbErrorState { error: db_error });
            app.manage(EmbeddedDbState {
                inner: std::sync::Mutex::new(embedded),
            });

            Ok(())
        })
        .on_window_event(|window, event| {
            if let tauri::WindowEvent::Destroyed = event {
                // Stop embedded postgres when the last window closes.
                if let Some(db_state) = window.try_state::<EmbeddedDbState>() {
                    if let Ok(mut guard) = db_state.inner.lock() {
                        if let Some(mut embedded) = guard.take() {
                            // stop_db is async — run it on a throw-away runtime.
                            let rt = tokio::runtime::Runtime::new();
                            if let Ok(rt) = rt {
                                let _ = rt.block_on(embedded.pg.stop_db());
                                eprintln!("[olympus-desktop] embedded postgres stopped cleanly");
                            }
                        }
                    }
                }
            }
        })
        .invoke_handler(tauri::generate_handler![get_api_port, get_db_error, commit_file])
        .run(tauri::generate_context!())
        .expect("failed to start Olympus desktop");
}
