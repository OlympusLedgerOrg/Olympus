@echo off
setlocal EnableDelayedExpansion

title Olympus Installer — Docker Desktop Package
cd /d "%~dp0"

set "PS=powershell.exe"
where pwsh.exe >nul 2>nul && set "PS=pwsh.exe"
set "START_LOG=%TEMP%\olympus-package-start.log"
set "COMPOSE=docker compose -f docker-compose.package.yml"

%PS% -Command "exit 0" >nul 2>nul
if errorlevel 1 (
  echo [X] PowerShell was not found. Install PowerShell, then run this again.
  pause
  exit /b 1
)

echo.
echo  Olympus local production package
echo  ================================================================
echo  This will bootstrap secrets, build containers, start Docker
echo  Compose, wait for health checks, then open the UI.
echo.
break > "%START_LOG%"
call :log "OLYMPUS_PROTOCOL package installer opened."
call :log "Loading splash art and Docker startup progress."
%PS% -NoProfile -ExecutionPolicy Bypass -Command "Get-CimInstance Win32_Process | Where-Object { $_.ProcessId -ne $PID -and $_.CommandLine -like '* -File *native-splash.ps1*' } | ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }" >nul 2>nul
start "" /min %PS% -NoProfile -ExecutionPolicy Bypass -File "%~dp0scripts\native-splash.ps1" -RepoRoot "%~dp0" -LogPath "%START_LOG%" -AppUrl "http://127.0.0.1:8080" -HealthUrl "http://127.0.0.1:8080/healthz" -Port 8777

echo [1/5] Bootstrapping .env and secrets ...
call :log "[1/5] Bootstrap starting."
%PS% -NoProfile -ExecutionPolicy Bypass -File "%~dp0scripts\bootstrap.ps1"
if errorlevel 1 (
  echo.
  echo [X] Bootstrap failed.
  call :log "[X] Bootstrap failed. See installer window."
  pause
  exit /b 1
)
call :log "[1/5] Bootstrap complete."

echo.
echo [2/5] Checking Docker Desktop ...
call :log "[2/5] Checking Docker Desktop."

rem Preflight: docker.exe must be on PATH before we do anything else.
where docker.exe >nul 2>nul
if errorlevel 1 (
  echo.
  echo [X] docker.exe was not found on PATH.
  echo     Install Docker Desktop for Windows, then run this again.
  start "" "https://www.docker.com/products/docker-desktop/"
  pause
  exit /b 1
)

rem Preflight: Compose V2 plugin must be present ("docker compose" not "docker-compose").
docker compose version >nul 2>nul
if errorlevel 1 (
  echo.
  echo [X] The Docker Compose V2 plugin is not available.
  echo     Update Docker Desktop to a recent version (4.x+) which bundles Compose V2.
  start "" "https://docs.docker.com/compose/install/"
  pause
  exit /b 1
)

docker info >nul 2>nul
if errorlevel 1 (
  if exist "%ProgramFiles%\Docker\Docker\Docker Desktop.exe" (
    echo     Docker is installed but not running. Starting Docker Desktop ...
    call :log "Starting Docker Desktop."
    start "" "%ProgramFiles%\Docker\Docker\Docker Desktop.exe"
  ) else if exist "%LOCALAPPDATA%\Docker\Docker Desktop.exe" (
    echo     Docker is installed but not running. Starting Docker Desktop ...
    call :log "Starting Docker Desktop."
    start "" "%LOCALAPPDATA%\Docker\Docker Desktop.exe"
  ) else (
    echo.
    echo [X] Docker Desktop is not installed or docker.exe is not on PATH.
    echo     Install Docker Desktop for Windows, start it once, then run this again.
    start "" "https://www.docker.com/products/docker-desktop/"
    pause
    exit /b 1
  )
)
docker info >nul 2>nul
if errorlevel 1 (
  echo     Waiting for Docker engine ...
  call :log "Waiting for Docker engine."
  set "TRIES=0"
  goto DOCKER_WAIT
)
goto DOCKER_READY

:DOCKER_WAIT
set /a TRIES+=1
if !TRIES! GTR 90 (
  echo.
  echo [X] Docker Desktop did not become ready after 3 minutes.
  echo     Open Docker Desktop and resolve any setup prompts, then run this again.
  pause
  exit /b 1
)
timeout /t 2 /nobreak >nul
docker info >nul 2>nul
if errorlevel 1 goto DOCKER_WAIT

:DOCKER_READY
echo     Docker is ready.
call :log "[2/5] Docker is ready."

echo.
echo [2b/5] Checking for an already-running Olympus package ...
call :log "[2b/5] Checking for an already-running Olympus package."
%PS% -NoProfile -Command "$ProgressPreference='SilentlyContinue'; try { Invoke-WebRequest -UseBasicParsing -TimeoutSec 2 'http://127.0.0.1:8080/healthz' | Out-Null; exit 0 } catch { exit 1 }" >nul 2>nul
if not errorlevel 1 (
  echo     Olympus UI is already running at http://127.0.0.1:8080
  call :log "Existing Olympus UI is healthy. Reusing it."
  start "" "http://127.0.0.1:8080"
  pause
  exit /b 0
)
for /f %%C in ('docker ps --filter "name=olympus-package-" --format "{{.Names}}" 2^>nul ^| find /c /v ""') do set "PACKAGE_RUNNING=%%C"
if not defined PACKAGE_RUNNING set "PACKAGE_RUNNING=0"
if not "%PACKAGE_RUNNING%"=="0" (
  echo     Found existing Olympus package containers. Reusing/updating them.
  call :log "Found existing Olympus package containers; compose will reuse/update them."
)

echo.
echo [3/5] Building and starting Olympus ...
echo     First run can take several minutes while Docker builds images.
call :log "[3/5] docker compose up -d --build starting. First run can take several minutes."
%COMPOSE% up -d --build --remove-orphans
if errorlevel 1 (
  echo.
  echo [X] Docker Compose failed.
  echo     Run this for details:
  echo       %COMPOSE% logs --tail=200
  call :log "[X] Docker Compose failed. See installer window."
  pause
  exit /b 1
)
call :log "[3/5] Docker Compose returned successfully."

echo.
echo [4/5] Waiting for API health ...
call :log "[4/5] Waiting for API health at http://127.0.0.1:8001/health."
set "TRIES=0"
:API_WAIT
set /a TRIES+=1
if !TRIES! GTR 90 (
  echo.
  echo [X] API did not become healthy after 3 minutes.
  echo     Run:
  echo       %COMPOSE% logs app
  pause
  exit /b 1
)
%PS% -NoProfile -Command "$ProgressPreference='SilentlyContinue'; try { Invoke-WebRequest -UseBasicParsing -TimeoutSec 2 'http://127.0.0.1:8001/health' | Out-Null; exit 0 } catch { exit 1 }" >nul 2>nul
if errorlevel 1 (
  timeout /t 2 /nobreak >nul
  goto API_WAIT
)
call :log "[4/5] API is healthy."

echo.
echo [5/5] Waiting for UI health ...
call :log "[5/5] Waiting for UI health at http://127.0.0.1:8080/healthz."
set "TRIES=0"
:UI_WAIT
set /a TRIES+=1
if !TRIES! GTR 60 (
  echo.
  echo [X] UI did not become healthy after 2 minutes.
  echo     Run:
  echo       %COMPOSE% logs public-ui
  pause
  exit /b 1
)
%PS% -NoProfile -Command "$ProgressPreference='SilentlyContinue'; try { Invoke-WebRequest -UseBasicParsing -TimeoutSec 2 'http://127.0.0.1:8080/healthz' | Out-Null; exit 0 } catch { exit 1 }" >nul 2>nul
if errorlevel 1 (
  timeout /t 2 /nobreak >nul
  goto UI_WAIT
)
call :log "[5/5] UI is healthy. Opening Olympus."

start "" "http://127.0.0.1:8080"

echo.
echo  Olympus is live.
echo  ------------------------------------------------
echo  UI:        http://127.0.0.1:8080
echo  API:       http://127.0.0.1:8001
echo  Stop:      %COMPOSE% down
echo  Logs:      %COMPOSE% logs -f
echo.
pause
exit /b 0

:log
>> "%START_LOG%" echo [%TIME%] %~1
exit /b 0
