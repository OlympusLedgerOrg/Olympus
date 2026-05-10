@echo off
setlocal

title Olympus Local App
cd /d "%~dp0"

where powershell.exe >nul 2>nul
if errorlevel 1 (
  echo [X] Windows PowerShell was not found.
  echo     Olympus setup needs the bundled Windows automation script.
  pause
  exit /b 1
)

echo ==================================================
echo    Olympus local app launcher
echo ==================================================
echo.
echo This will prepare/start:
echo   - PostgreSQL connection
echo   - Python API on http://localhost:8000
echo   - Public UX on http://localhost:5173
echo   - WSL CDHS-SMF and Go sequencer when WSL is available
echo.

if exist "%~dp0Olympus-Launcher.hta" (
  start "Olympus Launcher" mshta.exe "%~dp0Olympus-Launcher.hta"
)

powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0setup-windows.ps1" ^
  -StartDocker ^
  -ForceLocalDbUrl ^
  -EnableGoSequencer ^
  -UseWslSequencer ^
  -WslDbHost 127.0.0.1 ^
  -StartWslCdhsSmf ^
  -StartWslGoSequencer ^
  -HideServerWindows ^
  -OpenBrowser ^
  -BrowserUrl "http://localhost:5173" ^
  -CloseLauncherSplash ^
  %*

set exitcode=%ERRORLEVEL%
taskkill /FI "WINDOWTITLE eq Olympus Local App" /IM mshta.exe /F >nul 2>nul
if not "%exitcode%"=="0" (
  echo.
  echo [X] Olympus launcher exited with code %exitcode%.
  pause
)

exit /b %exitcode%
