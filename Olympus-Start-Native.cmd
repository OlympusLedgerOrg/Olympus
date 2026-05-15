@echo off
setlocal EnableExtensions

title Olympus Native (no Docker required)
cd /d "%~dp0"

:: Locate PowerShell
set "PS=powershell.exe"
where pwsh.exe >nul 2>nul && set "PS=pwsh.exe"
set "START_LOG=%TEMP%\olympus-native-start.log"

%PS% -Command "exit 0" >nul 2>nul
if errorlevel 1 (
  echo [X] PowerShell not found. Install PowerShell 7 and retry.
  pause & exit /b 1
)

echo.
echo  OLYMPUS_PROTOCOL
echo.
echo  Native launcher - no Docker, no PostgreSQL installer required
echo  =============================================================
echo.
break > "%START_LOG%"
call :log "OLYMPUS_PROTOCOL native launcher opened."
call :log "Loading splash art and startup progress."
%PS% -NoProfile -ExecutionPolicy Bypass -Command "Get-CimInstance Win32_Process | Where-Object { $_.ProcessId -ne $PID -and $_.CommandLine -like '* -File *native-splash.ps1*' } | ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }" >nul 2>nul
start "" /min %PS% -NoProfile -ExecutionPolicy Bypass -File "%~dp0scripts\native-splash.ps1" -RepoRoot "%~dp0" -LogPath "%START_LOG%" -AppUrl "http://127.0.0.1:8000"

:: Step 1: First-boot bootstrap (.env + secrets)
echo [1/3] Bootstrap ...
call :log "[1/3] Bootstrap starting."
%PS% -NoProfile -ExecutionPolicy Bypass -File "%~dp0scripts\bootstrap.ps1"
if errorlevel 1 (
  echo [X] Bootstrap failed. See output above.
  call :log "[X] Bootstrap failed. See main PowerShell window."
  pause & exit /b 1
)
call :log "[1/3] Bootstrap complete."

:: Step 2: Setup (deps + portable PostgreSQL + migrations)
echo.
echo [2/3] Setup  (Python deps, portable PostgreSQL, Alembic migrations) ...
echo       First run downloads PostgreSQL ~300 MB - subsequent runs are instant.
echo.
call :log "[2/3] Setup starting: dependencies, PostgreSQL 18 on 5433, migrations."
%PS% -NoProfile -ExecutionPolicy Bypass -File "%~dp0setup-windows.ps1" ^
     -UsePortablePostgres ^
     -ForceLocalDbUrl ^
     -DbPort 5433 ^
     -SkipRustBuild ^
     -SkipStart
if errorlevel 1 (
  echo [X] Setup failed. See output above.
  call :log "[X] Setup failed. See main PowerShell window."
  pause & exit /b 1
)
call :log "[2/3] Setup complete."

:: Step 3: Start the API (which also serves the pre-built UI)
echo.
echo [3/3] Starting API server ...
call :log "[3/3] Starting API server."
echo.
echo  ------------------------------------------------------------
echo  Olympus is starting
echo.
echo  UI + API:  http://127.0.0.1:8000
echo  Health:    http://127.0.0.1:8000/health
echo.
echo  To stop:   press Ctrl+C
echo  ------------------------------------------------------------
echo.

:: Load environment variables from .env (skip blank lines and comments)
if exist "%~dp0.env" (
  for /f "usebackq eol=# tokens=1,* delims==" %%A in ("%~dp0.env") do (
    if not "%%A"=="" if not "%%B"=="" (
      set "%%A=%%B"
    )
  )
)

:: Activate venv and launch uvicorn
if exist "%~dp0.venv\Scripts\activate.bat" (
  call "%~dp0.venv\Scripts\activate.bat"
)

uvicorn api.app:app --host 0.0.0.0 --port 8000

pause
exit /b 0

:log
>> "%START_LOG%" echo [%TIME%] %~1
exit /b 0
