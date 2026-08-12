// SPDX-License-Identifier: Apache-2.0

//! `main()`'s `on_window_event` handler body, extracted so the builder chain
//! in `main.rs` reads as `.on_window_event(handle_window_event)` instead of a
//! ~90-line inline closure.

use tauri::{Emitter, Manager};

/// Stop embedded postgres on the last window closing, and forward native OS
/// file-drop events to the frontend so the redaction tab can use the
/// path-based flow (no JS bytes).
pub(crate) fn handle_window_event(window: &tauri::Window, event: &tauri::WindowEvent) {
    match event {
        tauri::WindowEvent::Destroyed => {
            // Stop embedded postgres when the last window closes.
            if let Some(db_state) = window.try_state::<crate::commands::EmbeddedDbState>() {
                if let Ok(mut guard) = db_state.inner.lock() {
                    if let Some(mut embedded) = guard.take() {
                        // stop_db is async — run it on a throw-away runtime.
                        let data_dir = embedded.pg.pg_settings.database_dir.clone();
                        let rt = tokio::runtime::Runtime::new();
                        if let Ok(rt) = rt {
                            match rt.block_on(embedded.pg.stop_db()) {
                                Ok(()) => {
                                    match crate::db::confirm_and_disarm_embedded_postgres_reaper(
                                        &data_dir,
                                    ) {
                                        Ok(true) => {
                                            eprintln!(
                                                "[olympus-desktop] embedded postgres \
                                                 stopped cleanly"
                                            );
                                        }
                                        confirmation => {
                                            let error = match confirmation {
                                                Ok(false) => {
                                                    crate::db::DbError::UnsafeProcessCleanup(
                                                        "the retained PostgreSQL tree \
                                                         has not confirmed exit"
                                                            .to_owned(),
                                                    )
                                                }
                                                Err(error) => error,
                                                Ok(true) => unreachable!(),
                                            };
                                            let safe = crate::db::operator_safe_error(&error);
                                            eprintln!(
                                                "[olympus-desktop] exact-process stop \
                                                 returned but exit confirmation failed \
                                                 ({safe}); invoking \
                                                 retained-process cleanup"
                                            );
                                            if let Some(app_data_dir) = data_dir.parent() {
                                                let _ = crate::db::reap_embedded_pg(app_data_dir);
                                            }
                                        }
                                    }
                                }
                                Err(error) => {
                                    let error = crate::db::DbError::PgEmbed(error);
                                    let safe = crate::db::operator_safe_error(&error);
                                    eprintln!(
                                        "[olympus-desktop] embedded postgres stop failed: \
                                         {safe}; invoking retained-process cleanup"
                                    );
                                    if let Some(app_data_dir) = data_dir.parent() {
                                        if crate::db::reap_embedded_pg(app_data_dir) {
                                            let _ = embedded.pg.mark_process_stopped_externally();
                                        }
                                    }
                                }
                            }
                        } else if let Some(app_data_dir) = data_dir.parent() {
                            if crate::db::reap_embedded_pg(app_data_dir) {
                                let _ = embedded.pg.mark_process_stopped_externally();
                            }
                        }
                    }
                }
            }
        }
        // Forward native OS file-drop events to the frontend so the
        // redaction tab can use the path-based flow (no JS bytes).
        tauri::WindowEvent::DragDrop(tauri::DragDropEvent::Drop { paths, .. }) => {
            for path in paths {
                let name = path
                    .file_name()
                    .and_then(|s| s.to_str())
                    .unwrap_or("")
                    .to_owned();
                let _ = window.emit(
                    "file-dropped",
                    serde_json::json!({ "path": path.to_string_lossy(), "name": name }),
                );
            }
        }
        _ => {}
    }
}
