@echo off
setlocal EnableDelayedExpansion

title Olympus
cd /d "%~dp0"

:: ── Locate PowerShell ────────────────────────────────────────────────────────
set "PS=powershell.exe"
where pwsh.exe >nul 2>nul && set "PS=pwsh.exe"
set "COMPOSE=docker compose -f "%~dp0docker-compose.package.yml""
set "PODMAN_COMPOSE=podman compose -f "%~dp0docker-compose.package.yml""
set "START_LOG=%TEMP%\olympus-start.log"

%PS% -Command "exit 0" >nul 2>nul
if errorlevel 1 (
  echo [X] PowerShell not found. Install PowerShell 7 and retry.
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
echo  ================================================================
echo.

break > "%START_LOG%"
call :log "Olympus launcher opened."

:: Kill any stale splash from a previous run
%PS% -NoProfile -ExecutionPolicy Bypass -Command ^
  "Get-CimInstance Win32_Process | Where-Object { $_.ProcessId -ne $PID -and $_.CommandLine -like '* -File *native-splash.ps1*' } | ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }" ^
  >nul 2>nul

:: ── Step 1: First-boot bootstrap (.env + secrets) ───────────────────────────
echo [1/4] Bootstrap ...
call :log "[1/4] Bootstrap starting."
%PS% -NoProfile -ExecutionPolicy Bypass -File "%~dp0scripts\bootstrap.ps1"
if errorlevel 1 (
  echo [X] Bootstrap failed. See output above.
  call :log "[X] Bootstrap failed."
  pause & exit /b 1
)
call :log "[1/4] Bootstrap complete."

:: ── Step 2: Detect Podman (preferred) or Docker ─────────────────────────────
echo.
echo [2/4] Checking container runtime ...
call :log "[2/4] Probing container runtime."
set "USE_DOCKER=0"
set "USE_PODMAN=0"

:: ── Try Podman first (no daemon required) ────────────────────────────────────
where podman.exe >nul 2>nul
if not errorlevel 1 (
  podman info >nul 2>nul
  if not errorlevel 1 (
    set "USE_PODMAN=1"
    set "COMPOSE=%PODMAN_COMPOSE%"
    call :log "[2/4] Podman ready — using rootless Podman."
    echo     Podman is ready (rootless, no daemon required).
    goto RUNTIME_READY
  )
)

:: ── Fall back to Docker ───────────────────────────────────────────────────────
where docker.exe >nul 2>nul
if errorlevel 1 goto NO_RUNTIME

docker compose version >nul 2>nul
if errorlevel 1 goto NO_RUNTIME

docker info >nul 2>nul
if not errorlevel 1 (
  set "USE_DOCKER=1"
  goto DOCKER_READY
)

:: Docker installed but engine not running — try to start Desktop
if exist "%ProgramFiles%\Docker\Docker\Docker Desktop.exe" (
  echo     Starting Docker Desktop ...
  call :log "Starting Docker Desktop."
  start "" "%ProgramFiles%\Docker\Docker\Docker Desktop.exe"
) else if exist "%LOCALAPPDATA%\Docker\Docker Desktop.exe" (
  echo     Starting Docker Desktop ...
  call :log "Starting Docker Desktop."
  start "" "%LOCALAPPDATA%\Docker\Docker Desktop.exe"
) else (
  goto NO_RUNTIME
)

:: Wait up to 90 s for the engine to become ready
set "DTRIES=0"
:DOCKER_ENGINE_WAIT
set /a DTRIES+=1
if !DTRIES! GTR 45 goto NO_RUNTIME
timeout /t 2 /nobreak >nul
docker info >nul 2>nul
if errorlevel 1 goto DOCKER_ENGINE_WAIT
set "USE_DOCKER=1"
call :log "Docker engine ready."

:DOCKER_READY
echo     Docker is ready.
call :log "[2/4] Docker ready — using container stack."

:RUNTIME_READY

:: Start loading splash; it redirects to the app once /healthz is ready.
start "" /min %PS% -NoProfile -ExecutionPolicy Bypass ^
  -File "%~dp0scripts\native-splash.ps1" ^
  -RepoRoot "%~dp0" -LogPath "%START_LOG%" ^
  -AppUrl "http://127.0.0.1:8080" -HealthUrl "http://127.0.0.1:8080/healthz" -Port 8777

:: ── Step 3 (Docker): Build + start stack ────────────────────────────────────
echo.
echo [3/4] Starting stack  (docker compose up -d --build) ...
echo       First run builds images — may take a few minutes.
echo.
call :log "[3/4] docker compose up -d --build."
%COMPOSE% up -d --build --remove-orphans
if errorlevel 1 (
  echo.
  echo [X] docker compose failed. Common fixes:
  echo       - secrets\db_password missing  ^(re-run scripts\bootstrap.ps1^)
  echo       - DATABASE_NAME not set in .env  ^(check .env.example^)
  echo       - Port 8001 or 8080 already in use
  echo     Run  %COMPOSE% logs  for details.
  call :log "[X] docker compose failed."
  pause & exit /b 1
)
call :log "[3/4] Stack started."

:: ── Step 4 (Docker): Wait for UI health then open browser ───────────────────
echo.
echo [4/4] Waiting for UI health at http://127.0.0.1:8080/healthz ...
call :log "[4/4] Waiting for UI health."
set "TRIES=0"
:UI_HEALTH_WAIT
set /a TRIES+=1
if !TRIES! GTR 90 (
  echo [X] UI did not become healthy after 3 minutes.
  echo     Run: %COMPOSE% logs public-ui
  call :log "[X] UI health timed out."
  pause & exit /b 1
)
%PS% -NoProfile -Command ^
  "$ProgressPreference='SilentlyContinue'; try { Invoke-WebRequest -UseBasicParsing -TimeoutSec 2 'http://127.0.0.1:8080/healthz' | Out-Null; exit 0 } catch { exit 1 }" ^
  >nul 2>nul
if errorlevel 1 (
  timeout /t 2 /nobreak >nul
  goto UI_HEALTH_WAIT
)
call :log "[4/4] UI healthy. Splash will open the browser."

echo.
echo  -------------------------------------------------------
echo  Olympus is live
echo  -------------------------------------------------------
echo  Open:         http://127.0.0.1:8080
echo  Stop:         %COMPOSE% down
echo  Logs:         %COMPOSE% logs -f
echo.
pause
exit /b 0

:NO_RUNTIME
echo.
echo [X] No container runtime found. Options:
echo     1. Podman (recommended — no license, no daemon):
echo        winget install RedHat.Podman
echo        podman machine init ^&^& podman machine start
echo     2. Docker Desktop:
echo        https://www.docker.com/products/docker-desktop
echo.
call :log "[X] No container runtime — launcher exiting."
pause & exit /b 1

:log
>> "%START_LOG%" echo [%TIME%] %~1
exit /b 0
