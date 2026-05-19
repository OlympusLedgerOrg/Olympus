#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod integrity;
mod server;

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
            let (tx, rx) = std::sync::mpsc::channel();
            std::thread::spawn(move || {
                tokio::runtime::Runtime::new()
                    .expect("tokio runtime")
                    .block_on(async move {
                        let addr = server::start().await.expect("axum server failed to bind");
                        tx.send(addr.port()).expect("receiver dropped before port was sent");
                        // Park the thread so the tokio runtime (and the server task
                        // it owns) stays alive for the lifetime of the process.
                        std::future::pending::<()>().await;
                    });
            });
            let port = rx.recv().expect("axum server thread died before sending port");
            app.manage(ApiState { port });
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![get_api_port])
        .run(tauri::generate_context!())
        .expect("failed to start Olympus desktop");
}
