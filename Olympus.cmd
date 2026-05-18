@echo off
setlocal EnableDelayedExpansion

title Olympus
cd /d "%~dp0"

:: ── Locate PowerShell ────────────────────────────────────────────────────────
set "PS=powershell.exe"
where pwsh.exe >nul 2>nul && set "PS=pwsh.exe"
set "COMPOSE=docker compose -f "%~dp0docker-compose.package.yml""
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

:: ── Step 2: Detect Docker ───────────────────────────────────────────────────
echo.
echo [2/4] Checking Docker ...
call :log "[2/4] Probing Docker."
set "USE_DOCKER=0"

where docker.exe >nul 2>nul
if errorlevel 1 goto NO_DOCKER

docker compose version >nul 2>nul
if errorlevel 1 goto NO_DOCKER

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
  goto NO_DOCKER
)

:: Wait up to 90 s for the engine to become ready
set "DTRIES=0"
:DOCKER_ENGINE_WAIT
set /a DTRIES+=1
if !DTRIES! GTR 45 goto NO_DOCKER
timeout /t 2 /nobreak >nul
docker info >nul 2>nul
if errorlevel 1 goto DOCKER_ENGINE_WAIT
set "USE_DOCKER=1"
call :log "Docker engine ready."

:DOCKER_READY
echo     Docker is ready.
call :log "[2/4] Docker ready — using container stack."

:: Start splash for Docker mode (polls /healthz on 8080)
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
call :log "[4/4] UI healthy. Opening browser."

start "" "http://127.0.0.1:8080"

echo.
echo  -------------------------------------------------------
echo  Olympus is live  ^(Docker^)
echo  -------------------------------------------------------
echo  UI:           http://127.0.0.1:8080
echo  API:          http://127.0.0.1:8001
echo  TSA worker:   running ^(RFC 3161 timestamps^)
echo  Stop:         %COMPOSE% down
echo  Logs:         %COMPOSE% logs -f
echo  Worker logs:  %COMPOSE% logs -f tsa-worker
echo.
pause
exit /b 0

:: ============================================================================
:: Native fallback — Docker unavailable
:: ============================================================================
:NO_DOCKER
echo     Docker not available — switching to native mode ^(portable PostgreSQL^).
call :log "[2/4] Docker unavailable. Native mode."

:: Start splash for native mode (polls / on 8000)
start "" /min %PS% -NoProfile -ExecutionPolicy Bypass ^
  -File "%~dp0scripts\native-splash.ps1" ^
  -RepoRoot "%~dp0" -LogPath "%START_LOG%" ^
  -AppUrl "http://127.0.0.1:8000"

:: ── Step 3 (Native): Python deps + portable PostgreSQL + migrations ──────────
echo.
echo [3/4] Setup  ^(Python deps, portable PostgreSQL, Alembic migrations^) ...
echo       First run downloads PostgreSQL ~300 MB — subsequent runs are instant.
echo.
call :log "[3/4] Native setup starting."
%PS% -NoProfile -ExecutionPolicy Bypass -File "%~dp0setup-windows.ps1" ^
     -UsePortablePostgres ^
     -ForceLocalDbUrl ^
     -DbPort 5433 ^
     -SkipRustBuild ^
     -SkipStart
if errorlevel 1 (
  echo [X] Setup failed. See output above.
  call :log "[X] Native setup failed."
  pause & exit /b 1
)
call :log "[3/4] Native setup complete."

:: ── Step 4 (Native): TSA worker + API ───────────────────────────────────────
echo.
echo [4/4] Starting TSA worker + API ...
call :log "[4/4] Starting TSA worker and API."

:: Activate venv
if exist "%~dp0.venv\Scripts\activate.bat" call "%~dp0.venv\Scripts\activate.bat"

:: Load .env variables
if exist "%~dp0.env" (
  for /f "usebackq eol=# tokens=1,* delims==" %%A in ("%~dp0.env") do (
    if not "%%A"=="" if not "%%B"=="" set "%%A=%%B"
  )
)

:: TSA worker as minimised background window
where python.exe >nul 2>nul
if not errorlevel 1 (
  start "Olympus TSA Worker" /min python.exe -m api.workers.tsa_worker
  call :log "TSA worker started as Python subprocess."
  echo     TSA worker running in background window.
) else (
  echo     [!] python.exe not found — TSA worker not started.
  echo         Timestamps will stay pending until started manually.
  call :log "TSA worker skipped — python.exe not on PATH."
)

:: Start API (pre-built UI bundled, or Vite dev server)
if exist "%~dp0app\public-ui\dist\index.html" (
  echo.
  echo  -----------------------------------------------------------
  echo  Olympus is starting  ^(native — pre-built UI^)
  echo.
  echo  UI + API:  http://127.0.0.1:8000
  echo  Health:    http://127.0.0.1:8000/health
  echo  TSA:       background window
  echo.
  echo  To stop:   Ctrl+C here, then close the TSA worker window.
  echo  -----------------------------------------------------------
  echo.
  uvicorn api.app:app --host 127.0.0.1 --port 8000
) else (
  echo.
  echo  -----------------------------------------------------------
  echo  Olympus is starting  ^(native — Vite dev server^)
  echo.
  echo  UI:   http://127.0.0.1:5173
  echo  API:  http://127.0.0.1:8000
  echo  TSA:  background window
  echo.
  echo  A separate window opens for Vite. Close all to stop.
  echo  -----------------------------------------------------------
  echo.
  start "Olympus Vite Dev Server" cmd /k ^
    "cd /d "%~dp0app\public-ui" && npm run dev -- --host 127.0.0.1 --port 5173"
  timeout /t 3 /nobreak >nul
  start "" "http://127.0.0.1:5173"
  call :log "Vite dev server started."
  uvicorn api.app:app --host 127.0.0.1 --port 8000
)

pause
exit /b 0

:log
>> "%START_LOG%" echo [%TIME%] %~1
exit /b 0
