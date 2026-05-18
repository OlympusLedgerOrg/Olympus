// Prevents a terminal window appearing on Windows in release builds.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    olympus_tauri_lib::run();
}
