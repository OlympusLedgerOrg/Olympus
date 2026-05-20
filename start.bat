@echo off
cd /d "%~dp0"

set EXE=target\release\olympus-desktop.exe

:: ── build if binary is missing ───────────────────────────────────────────────
if not exist "%EXE%" (
    echo [Olympus] Building production release...
    cargo tauri build --no-bundle
    if errorlevel 1 (
        echo [Olympus] Build failed. See output above.
        pause
        exit /b 1
    )
)

:: ── launch ───────────────────────────────────────────────────────────────────
echo [Olympus] Starting Olympus Ledger...
start "" "%EXE%"
