#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]
// Match lib.rs: the bin re-includes the same module tree, so without this
// every item not reachable from `main` is reported as dead code.
#![allow(dead_code, unused_imports)]

mod anchoring;
mod api;
mod bootstrap;
mod db;
mod env;
#[cfg(feature = "federation")]
mod federation;
mod ingest_provenance;
mod integrity;
mod quorum;
mod routes;
mod server;
mod smt;
mod state;
mod zk;

use tauri::Manager;

// Tauri IPC commands + managed-state types, the startup-artifact /
// ceremony-verification helpers, `main()`'s orchestration phases, and the
// window-event handler were extracted from this file. `commands` and
// `startup` are glob-imported so `main()` and `generate_handler!` reference
// their items by bare name unchanged.
mod commands;
mod startup;
mod window_events;
use commands::*;
use startup::*;
use window_events::handle_window_event;
fn main() {
    // Initialise tracing → stderr so warn!/error! from request handlers and
    // background tasks (snapshot build, anchoring, etc.) are visible during
    // dev. Honour RUST_LOG; default to `info,olympus_desktop=debug` so our
    // own crate's warnings surface without drowning in third-party noise.
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| {
                tracing_subscriber::EnvFilter::new("info,olympus_desktop=debug")
            }),
        )
        .with_writer(std::io::stderr)
        .try_init();

    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .setup(|app| {
            let app_data_dir = app
                .path()
                .app_data_dir()
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::NotFound, e.to_string()))?;

            // Phase 1: best-effort cleanup if this process panics after PG
            // starts. The clean-exit path is handled by
            // `window_events::handle_window_event`'s `WindowEvent::Destroyed`
            // arm; this hook covers panics (e.g. setup-hook timeout) so the
            // next launch isn't blocked by an orphaned postgres.exe holding
            // port 5433.
            install_embedded_pg_panic_hook(app_data_dir.clone());

            // Phase 2: resolve the ZK artifacts directory and enforce every
            // production-only startup gate. Exits the process directly on a
            // fatal misconfiguration.
            let (is_prod, proofs_dir) = run_preflight_checks(app.handle());

            // Phase 3: hand DB connect / bootstrap / key resolution / crons /
            // federation bring-up / server::start to a dedicated Tokio
            // runtime thread, so the setup hook itself never blocks on it.
            let (tx, rx) = std::sync::mpsc::channel::<startup::StartupBringupResult>();
            let proofs_dir_for_thread = proofs_dir.clone();
            std::thread::spawn(move || {
                tokio::runtime::Runtime::new()
                    .expect("tokio runtime")
                    .block_on(run_server_bringup(app_data_dir, proofs_dir_for_thread, tx));
            });

            // Phase 4: register the managed state the app depends on, up
            // front and unpopulated.
            register_initial_managed_state(app.handle(), &proofs_dir, is_prod);

            // Phase 5: spawn the waiter thread that publishes the server
            // thread's eventual result (port, or a terminal startup error)
            // into the state Phase 4 registered.
            spawn_startup_waiter(app.handle().clone(), rx);

            Ok(())
        })
        .on_window_event(handle_window_event)
        .invoke_handler(tauri::generate_handler![
            get_api_port,
            get_db_error,
            commit_file,
            take_initial_secrets,
            get_startup_error,
            open_file_dialog,
            pick_file_path,
            hash_file_for_manifest,
            redact_by_path,
            describe_by_path,
            read_file_for_render,
            save_text_to_disk,
            keychain_get,
            keychain_set,
            keychain_delete,
        ])
        .run(tauri::generate_context!())
        .expect("failed to start Olympus desktop");
}
