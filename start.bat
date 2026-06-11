@echo off
:: Olympus Ledger launcher (Windows).
::
:: Mirrors start.sh: loads .env, pins the API port, builds the release
:: binary if missing, then runs it.
::
:: Usage: start.bat
::
:: To skip the build (e.g. you're iterating with `cargo tauri dev` and
:: only want to launch a pre-built binary): set NO_BUILD=1 before running.
::
:: Stale-postgres recovery (a postmaster.pid left by an unclean exit) is
:: handled inside the app itself (src-tauri/src/db.rs::try_init_embedded),
:: so the launcher doesn't need to clean it up.
setlocal
cd /d "%~dp0"

set "EXE=target\release\olympus-desktop.exe"

:: ── Load ./.env if the user has one (env-var overrides for keys, port, etc.) ──
:: Plain KEY=VALUE lines only (comments starting with # are skipped) — same
:: contract as start.sh. Values are taken verbatim; don't quote them in .env.
if exist ".env" (
    for /f "usebackq eol=# tokens=1,* delims==" %%A in (".env") do (
        if not "%%A"=="" if not "%%B"=="" set "%%A=%%B"
    )
)

:: ── Pin the API port so curl/scripts can find it without inspecting Tauri IPC ─
:: Users can override in .env or in their shell.
if not defined OLYMPUS_API_PORT set "OLYMPUS_API_PORT=3737"

:: ── Build if binary is missing ────────────────────────────────────────────────
if exist "%EXE%" goto :launch
if defined NO_BUILD goto :missing

where cargo >nul 2>nul
if errorlevel 1 (
    echo [Olympus] ERROR: cargo not found in PATH. Install Rust via https://rustup.rs/
    pause
    exit /b 1
)
cargo tauri --help >nul 2>nul
if errorlevel 1 (
    echo [Olympus] Installing tauri-cli ^(cargo install tauri-cli^)...
    cargo install tauri-cli --version "^2" --locked
)
echo [Olympus] Building production release (cargo tauri build --no-bundle)...
cargo tauri build --no-bundle
if errorlevel 1 (
    echo [Olympus] Build failed. See output above.
    pause
    exit /b 1
)

:missing
if not exist "%EXE%" (
    echo [Olympus] ERROR: binary not at %EXE%. Unset NO_BUILD or run cargo tauri build manually.
    pause
    exit /b 1
)

:launch
echo [Olympus] Starting Olympus Ledger (API on port %OLYMPUS_API_PORT%)...
start "" "%EXE%"
