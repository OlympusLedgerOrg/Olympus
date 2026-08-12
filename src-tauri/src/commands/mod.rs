// SPDX-License-Identifier: Apache-2.0

//! Tauri IPC command handlers and their managed-state types, split by domain:
//! [`server_state`] (API-port / DB-error / embedded-DB managed state),
//! [`secrets`] (one-shot bootstrap secrets + the in-app startup-error surface),
//! [`files`] (file-picker, hash, commit, redact, and render IPC commands), and
//! [`keychain`] (OS-keychain wrappers for the renderer-visible API key).
//!
//! The state structs are `pub(crate)` (constructed by `main`'s setup hook and
//! read by `on_window_event`); the `#[tauri::command]` handlers are
//! `pub(crate)` so `tauri::generate_handler!` in `main` can wire them. Every
//! item reachable via the old flat `commands.rs` stays reachable at
//! `crate::commands::*` through the re-exports below — `main.rs`'s
//! `use commands::*;` is unchanged by this split.

mod files;
mod keychain;
mod secrets;
mod server_state;

pub(crate) use files::{
    commit_file, describe_by_path, hash_file_for_manifest, open_file_dialog, pick_file_path,
    read_file_for_render, redact_by_path, save_text_to_disk, FileMeta, PickedFile, ProgressEvent,
};
pub(crate) use keychain::{keychain_delete, keychain_get, keychain_set};
pub(crate) use secrets::{
    clear_startup_timeout, get_startup_error, publish_startup_error, take_initial_secrets,
    InitialSecretsSerde, InitialSecretsState, StartupError, StartupErrorState,
    STARTUP_TIMEOUT_CODE,
};
pub(crate) use server_state::{
    get_api_port, get_db_error, ApiState, DbErrorState, EmbeddedDbState,
};
