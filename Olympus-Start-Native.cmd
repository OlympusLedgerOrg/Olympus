@echo off
setlocal EnableDelayedExpansion

title Olympus — Native  (no Docker required)
cd /d "%~dp0"

:: ── Locate PowerShell ──────────────────────────────────────────────────────
set "PS=powershell.exe"
where pwsh.exe >nul 2>nul && set "PS=pwsh.exe"

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
echo  Native launcher  —  no Docker, no PostgreSQL installer required
echo  ══════════════════════════════════════════════════════════════
echo.

:: ── Step 1: First-boot bootstrap (.env + secrets) ──────────────────────────
echo [1/3] Bootstrap ...
%PS% -NoProfile -ExecutionPolicy Bypass -File "%~dp0scripts\bootstrap.ps1"
if errorlevel 1 (
  echo [X] Bootstrap failed. See output above.
  pause & exit /b 1
)

:: ── Step 2: Setup (deps + portable PostgreSQL + migrations) ────────────────
echo.
echo [2/3] Setup  (Python deps, portable PostgreSQL, Alembic migrations) ...
echo       First run downloads PostgreSQL ~30 MB — subsequent runs are instant.
echo.
%PS% -NoProfile -ExecutionPolicy Bypass -File "%~dp0setup-windows.ps1" ^
     -UsePortablePostgres ^
     -ForceLocalDbUrl ^
     -SkipRustBuild ^
     -SkipStart
if errorlevel 1 (
  echo [X] Setup failed. See output above.
  pause & exit /b 1
)

:: ── Step 3: Start the API (which also serves the pre-built UI) ─────────────
echo.
echo [3/3] Starting API server ...
echo.
echo  ╔══════════════════════════════════════════════════════════╗
echo  ║  Olympus is starting                                    ║
echo  ║                                                          ║
echo  ║  UI + API  →  http://localhost:8000                     ║
echo  ║  Health    →  http://localhost:8000/health              ║
echo  ║                                                          ║
echo  ║  To stop:   press Ctrl+C                                ║
echo  ╚══════════════════════════════════════════════════════════╝
echo.

:: Activate venv and launch uvicorn
if exist "%~dp0.venv\Scripts\activate.bat" (
  call "%~dp0.venv\Scripts\activate.bat"
)

uvicorn api.app:app --host 0.0.0.0 --port 8000

pause
exit /b 0
