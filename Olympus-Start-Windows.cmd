@echo off
setlocal EnableExtensions EnableDelayedExpansion

title Olympus Native Launcher
cd /d "%~dp0"

set "PS=powershell.exe"
where pwsh.exe >nul 2>nul && set "PS=pwsh.exe"

%PS% -NoProfile -Command "exit 0" >nul 2>nul
if errorlevel 1 (
  echo [ERROR] PowerShell not found. Install PowerShell 7 or Windows PowerShell and retry.
  pause
  exit /b 1
)

if /I "%~1"=="--check" goto CHECK_ONLY

echo.
echo OLYMPUS NATIVE WINDOWS LAUNCHER
echo ============================================================
echo.
echo This launcher uses the native Windows development path:
echo   scripts\setup-windows.ps1
echo   scripts\doctor.ps1
echo   scripts\dev.ps1
echo.
echo It does not run Docker commands.
echo.

if not exist "%~dp0scripts\setup-windows.ps1" (
  echo [ERROR] Missing scripts\setup-windows.ps1
  pause
  exit /b 1
)
if not exist "%~dp0scripts\doctor.ps1" (
  echo [ERROR] Missing scripts\doctor.ps1
  pause
  exit /b 1
)
if not exist "%~dp0scripts\dev.ps1" (
  echo [ERROR] Missing scripts\dev.ps1
  pause
  exit /b 1
)

echo [1/4] Preparing native dependencies...
%PS% -NoProfile -ExecutionPolicy Bypass -File "%~dp0scripts\setup-windows.ps1"
if errorlevel 1 (
  echo.
  echo [ERROR] Native setup failed. See output above.
  pause
  exit /b 1
)

echo.
echo [2/4] Running native doctor...
%PS% -NoProfile -ExecutionPolicy Bypass -File "%~dp0scripts\doctor.ps1"
if errorlevel 1 (
  echo.
  echo [ERROR] Native doctor failed.
  echo [INFO] Make sure PostgreSQL 18 is running locally on 127.0.0.1:5432. PostgreSQL 16+ is supported.
  echo [INFO] Make sure psql is available on PATH.
  echo [INFO] The launcher did not start Docker.
  pause
  exit /b 1
)

echo.
echo [3/4] Starting splash screen...
if exist "%~dp0Olympus-Launcher.hta" (
  start "Olympus Launcher" mshta.exe "%~dp0Olympus-Launcher.hta"
) else (
  echo [WARN] Olympus-Launcher.hta not found; continuing without splash screen.
)

echo.
echo [4/4] Starting native API and UI...
echo [INFO] API will run at http://127.0.0.1:8000
echo [INFO] UI will run at http://127.0.0.1:5173
echo [INFO] Press Ctrl+C in this window to stop both services.
echo.

%PS% -NoProfile -ExecutionPolicy Bypass -File "%~dp0scripts\dev.ps1"
set "EXITCODE=%ERRORLEVEL%"

taskkill /FI "WINDOWTITLE eq Olympus Launcher" /IM mshta.exe /F >nul 2>nul

if not "%EXITCODE%"=="0" (
  echo.
  echo [ERROR] Native dev server exited with code %EXITCODE%.
  pause
  exit /b %EXITCODE%
)

exit /b 0

:CHECK_ONLY
echo [INFO] Checking Olympus-Start-Windows.cmd
if not exist "%~dp0scripts\setup-windows.ps1" (
  echo [ERROR] Missing scripts\setup-windows.ps1
  exit /b 1
)
if not exist "%~dp0scripts\doctor.ps1" (
  echo [ERROR] Missing scripts\doctor.ps1
  exit /b 1
)
if not exist "%~dp0scripts\dev.ps1" (
  echo [ERROR] Missing scripts\dev.ps1
  exit /b 1
)
%PS% -NoProfile -Command "$tokens=$null; $errors=$null; foreach ($f in @('scripts\setup-windows.ps1','scripts\doctor.ps1','scripts\dev.ps1')) { [System.Management.Automation.Language.Parser]::ParseFile($f,[ref]$tokens,[ref]$errors) | Out-Null; if ($errors) { $errors | Format-List; exit 1 } }; exit 0"
if errorlevel 1 (
  echo [ERROR] PowerShell script parse check failed.
  exit /b 1
)
echo [OK] Launcher check passed.
exit /b 0
