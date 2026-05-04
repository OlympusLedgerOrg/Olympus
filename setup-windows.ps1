#Requires -Version 5.1
<#
.SYNOPSIS
    One-command setup for Olympus on Windows.

.DESCRIPTION
    Checks prerequisites, starts a PostgreSQL Docker container, creates a
    Python virtual environment, installs dependencies, runs database
    migrations, and starts the API on http://localhost:8000.

.PARAMETER DbUser
    PostgreSQL username (default: olympus).

.PARAMETER DbPassword
    PostgreSQL password (default: olympus).  Use a strong password in
    any environment that is reachable from outside your machine.

.PARAMETER SkipDocker
    Skip the PostgreSQL Docker container step (use if you already have
    Postgres running externally).

.PARAMETER SkipStart
    Set up everything but do not start the API server at the end.

.EXAMPLE
    .\setup-windows.ps1

.EXAMPLE
    .\setup-windows.ps1 -DbUser myuser -DbPassword s3cr3t

.EXAMPLE
    .\setup-windows.ps1 -SkipDocker
#>
param(
    [string]$DbUser     = "olympus",
    [string]$DbPassword = "olympus",
    [switch]$SkipDocker,
    [switch]$SkipStart
)

$ErrorActionPreference = "Stop"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
function Write-Step  { param($msg) Write-Host "`n[*] $msg" -ForegroundColor Cyan }
function Write-Ok    { param($msg) Write-Host "    [+] $msg" -ForegroundColor Green }
function Write-Warn  { param($msg) Write-Host "    [!] $msg" -ForegroundColor Yellow }
function Write-Fail  { param($msg) Write-Host "`n[X] $msg" -ForegroundColor Red; exit 1 }

# ---------------------------------------------------------------------------
# Banner
# ---------------------------------------------------------------------------
Write-Host ""
Write-Host "==================================================" -ForegroundColor Cyan
Write-Host "   Olympus -- one-command setup (Windows)        " -ForegroundColor Cyan
Write-Host "==================================================" -ForegroundColor Cyan

# ---------------------------------------------------------------------------
# 1. Prerequisites
# ---------------------------------------------------------------------------
Write-Step "Checking prerequisites"

# Python 3.10-3.13
try {
    $pyRaw = python --version 2>&1
} catch {
    Write-Fail "Python not found. Install Python 3.10-3.13 (3.12 recommended) from https://python.org and re-run."
}
if ($pyRaw -notmatch "3\.(1[0-3])(\.|$)") {
    Write-Fail "Python 3.10-3.13 is currently supported (found: $pyRaw). Use Python 3.12 for best compatibility: https://python.org."
}
Write-Ok "$pyRaw"

# Optional ZK/prover toolchain checks (snarkjs / rapidsnark workflows)
$npxCmd = Get-Command npx -ErrorAction SilentlyContinue
if ($null -eq $npxCmd) {
    Write-Warn "npx not found. ZK tooling (snarkjs/rapidsnark workflows) may fail until Node.js is installed."
} else {
    Write-Ok "npx detected: $($npxCmd.Source)"
}

$nasmCmd = Get-Command nasm -ErrorAction SilentlyContinue
if ($null -eq $nasmCmd) {
    Write-Warn "nasm not found. rapidsnark builds that compile ffiasm-generated .asm files may fail."
    Write-Warn "Install Netwide Assembler (nasm) and ensure it is on PATH for proof-generation workflows."
} else {
    Write-Ok "nasm detected: $($nasmCmd.Source)"
}

# Docker (only needed when not skipped)
if (-not $SkipDocker) {
    try {
        $dockerVer = docker --version 2>&1
    } catch {
        Write-Fail "Docker not found. Install Docker Desktop from https://www.docker.com/products/docker-desktop and re-run."
    }
    Write-Ok "$dockerVer"
}

# ---------------------------------------------------------------------------
# 2. PostgreSQL via Docker
# ---------------------------------------------------------------------------
if (-not $SkipDocker) {
    Write-Step "Starting PostgreSQL (Docker)"

    $running = docker ps --filter "name=olympus-postgres" --format "{{.Names}}" 2>$null
    if ($running -eq "olympus-postgres") {
        Write-Ok "Container 'olympus-postgres' is already running -- reusing it."
    } else {
        # Remove stopped container with the same name if it exists
        $stopped = docker ps -a --filter "name=olympus-postgres" --format "{{.Names}}" 2>$null
        if ($stopped -eq "olympus-postgres") {
            Write-Warn "Removing stopped 'olympus-postgres' container..."
            docker rm olympus-postgres | Out-Null
        }

        docker run `
            --name olympus-postgres `
            -e POSTGRES_USER=$DbUser `
            -e POSTGRES_PASSWORD=$DbPassword `
            -e POSTGRES_DB=olympus `
            -p 5432:5432 `
            -d postgres:16 | Out-Null

        Write-Ok "Container started -- waiting up to 30 s for Postgres to be ready..."

        $ready = $false
        for ($i = 0; $i -lt 30; $i++) {
            Start-Sleep -Seconds 1
            $pg = docker exec olympus-postgres pg_isready -U $DbUser -d olympus 2>$null
            if ($LASTEXITCODE -eq 0) { $ready = $true; break }
        }
        if (-not $ready) {
            Write-Fail "Postgres did not become ready in 30 s. Run: docker logs olympus-postgres"
        }
        Write-Ok "PostgreSQL is ready."
    }
}

# ---------------------------------------------------------------------------
# 3. Environment variables
# ---------------------------------------------------------------------------
Write-Step "Setting environment variables"

if (-not $env:DATABASE_URL) {
    $env:DATABASE_URL = "postgresql://${DbUser}:${DbPassword}@localhost:5432/olympus"
    Write-Ok "DATABASE_URL set to postgresql://${DbUser}:***@localhost:5432/olympus"
} else {
    Write-Ok "DATABASE_URL already set -- using existing value."
}

if (-not $env:OLYMPUS_INGEST_SIGNING_KEY) {
    # Generate a random 32-byte key at setup time so it survives restarts.
    $keyBytes = New-Object byte[] 32
    [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($keyBytes)
    $env:OLYMPUS_INGEST_SIGNING_KEY = ($keyBytes | ForEach-Object { $_.ToString("x2") }) -join ""
    Write-Ok "OLYMPUS_INGEST_SIGNING_KEY generated (random 32-byte key)."
    Write-Warn "Persist this key in your .env file to keep ledger entries verifiable:"
    Write-Host "   OLYMPUS_INGEST_SIGNING_KEY=$env:OLYMPUS_INGEST_SIGNING_KEY" -ForegroundColor Yellow
} else {
    Write-Ok "OLYMPUS_INGEST_SIGNING_KEY already set -- using existing value."
}

# Convenience: also write a .env file so subsequent runs pick up the same values
$envFile = Join-Path $PSScriptRoot ".env"
if (-not (Test-Path $envFile)) {
    @"
# Auto-generated by setup-windows.ps1 -- edit as needed.
DATABASE_URL=$env:DATABASE_URL
OLYMPUS_INGEST_SIGNING_KEY=$env:OLYMPUS_INGEST_SIGNING_KEY
OLYMPUS_DEV_SIGNING_KEY=false
"@ | Set-Content -Encoding UTF8 $envFile
    Write-Ok ".env file written to $envFile"
} else {
    Write-Ok ".env already exists -- not overwriting."
}

# ---------------------------------------------------------------------------
# 4. Python virtual environment
# ---------------------------------------------------------------------------
Write-Step "Setting up Python virtual environment"

$venvDir = Join-Path $PSScriptRoot ".venv"
if (-not (Test-Path $venvDir)) {
    python -m venv $venvDir
    Write-Ok "Virtual environment created at .venv"
} else {
    Write-Ok "Virtual environment already exists at .venv"
}

# Activate
$activateScript = Join-Path $venvDir "Scripts\Activate.ps1"
if (-not (Test-Path $activateScript)) {
    Write-Fail "Cannot find .venv\Scripts\Activate.ps1 -- virtual environment may be corrupted. Delete .venv and re-run."
}
. $activateScript
Write-Ok "Virtual environment activated."

# ---------------------------------------------------------------------------
# 5. Install dependencies
# ---------------------------------------------------------------------------
Write-Step "Installing Python dependencies (this may take a few minutes)"

python -m pip install --upgrade pip --quiet
pip install --quiet -r (Join-Path $PSScriptRoot "requirements.txt")
if (Test-Path (Join-Path $PSScriptRoot "requirements-dev.txt")) {
    pip install --quiet -r (Join-Path $PSScriptRoot "requirements-dev.txt")
}
pip install --quiet -e (Join-Path $PSScriptRoot ".[dev]") 2>$null
if ($LASTEXITCODE -ne 0) {
    # Fall back to plain install if [dev] extra is not defined
    pip install --quiet -e $PSScriptRoot
}
Write-Ok "Dependencies installed."

# ---------------------------------------------------------------------------
# 6. Database migrations
# ---------------------------------------------------------------------------
Write-Step "Running Alembic database migrations"

Push-Location $PSScriptRoot
try {
    python -m alembic upgrade head
} catch {
    Write-Fail "Alembic migration failed: $_`nCheck DATABASE_URL and that PostgreSQL is reachable."
} finally {
    Pop-Location
}
Write-Ok "Database schema is up to date."

# ---------------------------------------------------------------------------
# 7. Success summary
# ---------------------------------------------------------------------------
Write-Host ""
Write-Host "==================================================" -ForegroundColor Green
Write-Host "   Setup complete!                               " -ForegroundColor Green
Write-Host "==================================================" -ForegroundColor Green
Write-Host "   API:      http://localhost:8000               " -ForegroundColor Green
Write-Host "   API docs: http://localhost:8000/docs          " -ForegroundColor Green
Write-Host "   Database: postgresql://${DbUser}@localhost:5432/olympus" -ForegroundColor Green
Write-Host "==================================================" -ForegroundColor Green

if ($SkipStart) {
    Write-Host "`nTo start the API later run:" -ForegroundColor Cyan
    Write-Host "  .\.venv\Scripts\Activate.ps1" -ForegroundColor White
    Write-Host "  uvicorn api.app:app --reload --host 0.0.0.0 --port 8000" -ForegroundColor White
    exit 0
}

# ---------------------------------------------------------------------------
# 8. Start API server
# ---------------------------------------------------------------------------
Write-Host ""
Write-Host "Starting API server -- press Ctrl+C to stop." -ForegroundColor Cyan
Write-Host ""

uvicorn api.app:app --reload --host 0.0.0.0 --port 8000
