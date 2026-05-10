@echo off
setlocal EnableDelayedExpansion

title Olympus — Docker Compose
cd /d "%~dp0"

:: ── Locate PowerShell ──────────────────────────────────────────────────────
set "PS=powershell.exe"
where pwsh.exe >nul 2>nul && set "PS=pwsh.exe"

%PS% -Command "exit 0" >nul 2>nul
if errorlevel 1 (
  echo [X] PowerShell not found. Install PowerShell 7 and retry.
  taskkill /FI "WINDOWTITLE eq Olympus Launcher" /IM mshta.exe /F >nul 2>nul
  pause & exit /b 1
)

echo.
echo  ██████╗ ██╗  ██╗   ██╗███╗   ███╗██████╗ ██╗   ██╗███████╗
echo  ██╔═══██╗██║  ╚██╗ ██╔╝████╗ ████║██╔══██╗██║   ██║██╔════╝
echo  ██║   ██║██║   ╚████╔╝ ██╔████╔██║██████╔╝██║   ██║███████╗
echo  ██║   ██║██║    ╚██╔╝  ██║╚██╔╝██║██╔═══╝ ██║   ██║╚════██║
echo  ╚██████╔╝███████╗██║   ██║ ╚═╝ ██║██║     ╚██████╔╝███████║
echo   ╚═════╝ ╚══════╝╚═╝   ╚═╝     ╚═╝╚═╝      ╚═════╝ ╚══════╝
echo.
echo  Docker Compose stack launcher
echo  ══════════════════════════════════════════════════════════════
echo.

:: ── Splash: launch the HTA loading screen ──────────────────────────────────
:: The HTA polls the API + UI itself, then opens the browser and closes.
if exist "%~dp0Olympus-Launcher.hta" (
  start "Olympus Launcher" mshta.exe "%~dp0Olympus-Launcher.hta"
)

:: ── Step 1: First-boot bootstrap (.env + secrets) ──────────────────────────
echo [1/4] Bootstrap ...
%PS% -NoProfile -ExecutionPolicy Bypass -File "%~dp0scripts\bootstrap.ps1"
if errorlevel 1 (
  echo [X] Bootstrap failed. See output above.
  taskkill /FI "WINDOWTITLE eq Olympus Launcher" /IM mshta.exe /F >nul 2>nul
  pause & exit /b 1
)

:: ── Step 2: Verify Docker is reachable ─────────────────────────────────────
echo.
echo [2/4] Checking Docker ...
docker info >nul 2>nul
if errorlevel 1 (
  echo.
  echo [X] Docker is not running.
  echo     Start Docker Desktop, wait for the tray icon to show "Running",
  echo     then relaunch this script.
  taskkill /FI "WINDOWTITLE eq Olympus Launcher" /IM mshta.exe /F >nul 2>nul
  pause & exit /b 1
)
echo     Docker is ready.

:: ── Step 3: docker compose up ──────────────────────────────────────────────
echo.
echo [3/4] Starting stack  (docker compose up -d --build) ...
echo       This rebuilds images on first run — may take a few minutes.
echo.
docker compose up -d --build
if errorlevel 1 (
  echo.
  echo [X] docker compose up failed. Check the output above.
  echo     Common fixes:
  echo       - secrets\db_password missing  (re-run scripts\bootstrap.ps1)
  echo       - DATABASE_NAME not set in .env (check .env.example)
  echo       - Port 8001 or 8080 already in use
  taskkill /FI "WINDOWTITLE eq Olympus Launcher" /IM mshta.exe /F >nul 2>nul
  pause & exit /b 1
)

:: ── Step 4: Wait for API health ────────────────────────────────────────────
echo.
echo [4/4] Waiting for API health at http://localhost:8001/health ...
set "TRIES=0"
:HEALTH_LOOP
set /a TRIES+=1
if %TRIES% GTR 60 (
  echo.
  echo [X] API did not become healthy after 60 attempts (^~2 min).
  echo     Run  docker compose logs app  to see startup errors.
  taskkill /FI "WINDOWTITLE eq Olympus Launcher" /IM mshta.exe /F >nul 2>nul
  pause & exit /b 1
)
%PS% -NoProfile -Command ^
  "try { $r=(Invoke-WebRequest -Uri 'http://localhost:8001/health' -UseBasicParsing -TimeoutSec 2 -ErrorAction Stop); exit 0 } catch { exit 1 }" ^
  >nul 2>nul
if errorlevel 1 (
  timeout /t 2 /nobreak >nul
  goto HEALTH_LOOP
)

:: ── Open the UI in the default browser ────────────────────────────────────
start "" "http://localhost:8080"

:: ── Done ───────────────────────────────────────────────────────────────────
echo.
echo  ╔══════════════════════════════════════════════════════════╗
echo  ║  Olympus is live                                        ║
echo  ║                                                          ║
echo  ║  Public UI   →  http://localhost:8080                   ║
echo  ║  API         →  http://localhost:8001                   ║
echo  ║  Sequencer   →  http://localhost:8081  (internal)       ║
echo  ║                                                          ║
echo  ║  To stop:   docker compose down                         ║
echo  ║  Logs:      docker compose logs -f                      ║
echo  ╚══════════════════════════════════════════════════════════╝
echo.

exit /b 0
