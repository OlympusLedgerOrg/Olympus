@echo off
setlocal

title Olympus Local App
cd /d "%~dp0"

set "OLYMPUS_PS=powershell.exe"

where pwsh.exe >nul 2>nul
if not errorlevel 1 (
  set "OLYMPUS_PS=pwsh.exe"
)

where "%OLYMPUS_PS%" >nul 2>nul
if errorlevel 1 (
  echo [X] PowerShell was not found.
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

"%OLYMPUS_PS%" -NoProfile -ExecutionPolicy Bypass -File "%~dp0setup-windows.ps1" ^
  -StartDocker ^
  -ForceLocalDbUrl ^
  -EnableGoSequencer ^
  -UseWslSequencer ^
  -WslDbHost 127.0.0.1 ^
  -StartWslCdhsSmf ^
  -StartWslGoSequencer ^
  -HideServerWindows ^
  %*

set exitcode=%ERRORLEVEL%
if not "%exitcode%"=="0" (
  taskkill /FI "WINDOWTITLE eq Olympus Local App" /IM mshta.exe /F >nul 2>nul
  echo.
  echo [X] Olympus launcher exited with code %exitcode%.
  pause
)

exit /b %exitcode%
