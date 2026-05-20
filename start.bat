@echo off
cd /d "%~dp0"
set OLYMPUS_API_PORT=8000
cargo tauri dev
pause
