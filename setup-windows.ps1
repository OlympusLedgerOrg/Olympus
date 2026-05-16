#Requires -Version 5.1
<#
.SYNOPSIS
    Dev-safe Windows setup for Olympus, with optional WSL live sequencer support.

.DESCRIPTION
    This script prepares local Windows dev:
      - Loads .env
      - Forces local PostgreSQL URLs if requested
      - Normalizes integer env vars like MAX_UPLOAD_BYTES
      - Creates/activates .venv
      - Installs Python deps
      - Builds Rust/Python extension with maturin
      - Installs/starts the public UX
      - Builds/tests Go sequencer on Windows
      - Optionally starts CDHS-SMF + Go sequencer inside WSL because CDHS-SMF uses Unix sockets

    Important:
      Native Windows can build/test the Go sequencer, but the live daemon path depends on
      CDHS-SMF over a Unix socket. Use -UseWslSequencer -StartWslCdhsSmf -StartWslGoSequencer
      for the live smoke-test path.
#>

param(
    [string]$DbUser     = "olympus",
    [string]$DbPassword = "olympus",
    [string]$DbHost     = "127.0.0.1",
    [int]$DbPort        = 5432,
    [string]$DbName     = "olympus",

    # When running the full stack via Docker Compose, use Docker service names
    # instead of host IPs. Sets DbHost=db and sequencer URL=http://sequencer-go:8081.
    [switch]$DockerMode,

    [switch]$StartDocker,
    [switch]$SkipDocker,
    [switch]$ForceLocalDbUrl,

    [switch]$SkipInstall,
    [switch]$SkipRustBuild,
    [switch]$ReleaseRustBuild,

    [switch]$EnableGoSequencer,
    [switch]$BuildGoSequencer,
    [switch]$TestGoSequencer,
    [switch]$StartGoSequencer,
    [switch]$RunSequencerSmokeTests,

    [ValidateSet("url", "components")]
    [string]$SequencerDbMode = "url",

    [string]$SequencerHttpAddr = "127.0.0.1:8081",
    [string]$SequencerUrl = "http://localhost:8081",

    [switch]$UseWslSequencer,
    [switch]$StartWslCdhsSmf,
    [switch]$StartWslGoSequencer,
    [string]$WslDistro = "",
    [string]$WslRepoPath = "",
    [string]$WslCdhsSocket = "/run/olympus/cdhs-smf.sock",
    [string]$WslSequencerHttpAddr = "0.0.0.0:8081",
    [string]$WslDbHost = "auto",

    [switch]$RequireGoSequencer,
    [switch]$SkipGoSequencer,

    # Auto-download and run a portable PostgreSQL 16 binary (no Docker, no installer).
    # Binaries are extracted to vendor\pgsql\; data lives in vendor\pgdata\.
    # Neither directory is committed (.gitignore excludes them).
    [switch]$UsePortablePostgres,
    [string]$PortablePostgresUrl = "https://get.enterprisedb.com/postgresql/postgresql-16.6-1-windows-x64-binaries.zip",

    [switch]$SkipMigrations,
    [switch]$SkipFirstBoot,
    [switch]$StampHead,
    [switch]$ResetDb,
    [switch]$SkipUi,
    [int]$UiPort = 5173,
    [switch]$HideServerWindows,
    [switch]$OpenBrowser,
    [string]$BrowserUrl = "",
    [switch]$CloseLauncherSplash,
    [switch]$SkipStart
)

$ErrorActionPreference = "Stop"

# Default HideServerWindows to $true so spawned processes never open visible
# console windows unless the caller explicitly passes -HideServerWindows:$false.
if (-not $PSBoundParameters.ContainsKey('HideServerWindows')) {
    $HideServerWindows = $true
}

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

function Write-Step {
    param([string]$msg)
    Write-Host "`n[*] $msg" -ForegroundColor Cyan
}

function Write-Ok {
    param([string]$msg)
    Write-Host "    [+] $msg" -ForegroundColor Green
}

function Write-Warn {
    param([string]$msg)
    Write-Host "    [!] $msg" -ForegroundColor Yellow
}

function Write-Fail {
    param([string]$msg)
    Write-Host "`n[X] $msg" -ForegroundColor Red
    exit 1
}

function Test-Command {
    param([string]$Name)
    return [bool](Get-Command $Name -ErrorAction SilentlyContinue)
}

function Get-PowerShellHost {
    $pwsh = Get-Command "pwsh.exe" -ErrorAction SilentlyContinue
    if ($pwsh) {
        return $pwsh.Source
    }

    $windowsPowerShell = Get-Command "powershell.exe" -ErrorAction SilentlyContinue
    if ($windowsPowerShell) {
        return $windowsPowerShell.Source
    }

    return "powershell.exe"
}

function Ensure-DockerDesktopRunning {
    Write-Step "Checking Docker Desktop / Docker engine"

    if (-not (Test-Command "docker")) {
        Write-Fail "Docker CLI not found. Install Docker Desktop or run without -StartDocker."
    }

    try {
        docker info *> $null
        if ($LASTEXITCODE -eq 0) {
            Write-Ok "Docker engine is already running."
            return
        }
    } catch {
        # Docker CLI exists, but the engine is not ready yet.
    }

    $dockerDesktopCandidates = @(
        "$env:ProgramFiles\Docker\Docker\Docker Desktop.exe",
        "${env:ProgramFiles(x86)}\Docker\Docker\Docker Desktop.exe",
        "$env:LOCALAPPDATA\Docker\Docker Desktop.exe"
    )

    $dockerDesktop = $dockerDesktopCandidates |
        Where-Object { $_ -and (Test-Path $_) } |
        Select-Object -First 1

    if (-not $dockerDesktop) {
        Write-Fail "Docker Desktop executable was not found. Start Docker Desktop manually or install it."
    }

    Write-Warn "Docker engine is not running. Starting Docker Desktop."
    Start-Process -FilePath $dockerDesktop -WindowStyle Hidden | Out-Null

    Write-Warn "Waiting for Docker engine to become ready."

    for ($i = 1; $i -le 90; $i++) {
        Start-Sleep -Seconds 2

        try {
            docker info *> $null
            if ($LASTEXITCODE -eq 0) {
                Write-Ok "Docker engine is ready."
                return
            }
        } catch {
            # keep waiting
        }

        if (($i % 5) -eq 0) {
            Write-Warn "Still waiting for Docker engine... attempt $i/90"
        }
    }

    Write-Fail "Docker Desktop was started, but the Docker engine did not become ready. Open Docker Desktop and check for errors."
}


function Mask-DatabaseUrl {
    param([string]$Url)

    if (-not $Url) {
        return "<empty>"
    }

    return ($Url -replace '://([^:/@]+):([^@]+)@', '://${1}:***@')
}

function Load-DotEnv {
    param([string]$Path)

    if (-not (Test-Path $Path)) {
        Write-Warn ".env not found at $Path"
        return
    }

    Get-Content $Path | ForEach-Object {
        $line = $_.Trim()

        if (-not $line) { return }
        if ($line.StartsWith("#")) { return }
        if (-not $line.Contains("=")) { return }

        $name, $value = $line -split "=", 2
        $name = $name.Trim()
        $value = $value.Trim()

        if (
            ($value.StartsWith('"') -and $value.EndsWith('"')) -or
            ($value.StartsWith("'") -and $value.EndsWith("'"))
        ) {
            $value = $value.Substring(1, $value.Length - 2)
        }

        if (-not [Environment]::GetEnvironmentVariable($name, "Process")) {
            [Environment]::SetEnvironmentVariable($name, $value, "Process")
        }
    }

    Write-Ok ".env loaded into current PowerShell process."
}

function Set-DotEnvValue {
    param(
        [string]$Path,
        [string]$Key,
        [string]$Value
    )

    if (-not (Test-Path $Path)) {
        New-Item -Path $Path -ItemType File -Force | Out-Null
    }

    $lines = @(Get-Content $Path -ErrorAction SilentlyContinue)
    $found = $false
    $updated = @()

    foreach ($line in $lines) {
        if ($line -match "^\s*$([regex]::Escape($Key))=") {
            $updated += "$Key=$Value"
            $found = $true
        } else {
            $updated += $line
        }
    }

    if (-not $found) {
        $updated += "$Key=$Value"
    }

    $updated | Set-Content -Path $Path -Encoding UTF8
}

function Remove-DotEnvKey {
    param(
        [string]$Path,
        [string]$Key
    )

    if (-not (Test-Path $Path)) {
        return
    }

    $lines = @(Get-Content $Path -ErrorAction SilentlyContinue)
    $updated = @()

    foreach ($line in $lines) {
        if ($line -match "^\s*$([regex]::Escape($Key))=") {
            continue
        }

        $updated += $line
    }

    $updated | Set-Content -Path $Path -Encoding UTF8
}

function Save-DotEnvIfMissing {
    param([string]$Path)

    if (Test-Path $Path) {
        Write-Ok ".env already exists -- not overwriting."
        return
    }

    @"
# Auto-generated by setup-windows.ps1 -- edit as needed.
DATABASE_URL=$env:DATABASE_URL
PSYCOPG_URL=$env:PSYCOPG_URL
MAX_UPLOAD_BYTES=$env:MAX_UPLOAD_BYTES
OLYMPUS_INGEST_SIGNING_KEY=$env:OLYMPUS_INGEST_SIGNING_KEY
OLYMPUS_DEV_SIGNING_KEY=false
OLYMPUS_USE_GO_SEQUENCER=$env:OLYMPUS_USE_GO_SEQUENCER
OLYMPUS_SEQUENCER_TOKEN=$env:OLYMPUS_SEQUENCER_TOKEN
SEQUENCER_API_TOKEN=$env:SEQUENCER_API_TOKEN
GO_SEQUENCER_URL=$env:GO_SEQUENCER_URL
SEQUENCER_HTTP_ADDR=$env:SEQUENCER_HTTP_ADDR
SEQUENCER_ALLOW_INSECURE_DB=$env:SEQUENCER_ALLOW_INSECURE_DB
"@ | Set-Content -Encoding UTF8 $Path

    Write-Ok ".env written to $Path"
}

function New-RandomHexKey {
    $keyBytes = New-Object byte[] 32
    [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($keyBytes)
    return ($keyBytes | ForEach-Object { $_.ToString("x2") }) -join ""
}

function Test-TcpPort {
    param(
        [string]$HostName,
        [int]$Port
    )

    try {
        $client = New-Object System.Net.Sockets.TcpClient
        $iar = $client.BeginConnect($HostName, $Port, $null, $null)
        $success = $iar.AsyncWaitHandle.WaitOne(1000, $false)

        if ($success) {
            $client.EndConnect($iar)
            $client.Close()
            return $true
        }

        $client.Close()
        return $false
    } catch {
        return $false
    }
}

function Get-HostAndPortFromAddr {
    param([string]$Addr)

    $parts = $Addr -split ":", 2
    if ($parts.Count -ne 2) {
        return @{ Host = "127.0.0.1"; Port = 8081 }
    }

    $hostPart = $parts[0]
    if (-not $hostPart -or $hostPart -eq "0.0.0.0") {
        $hostPart = "127.0.0.1"
    }

    return @{
        Host = $hostPart
        Port = [int]$parts[1]
    }
}

function Invoke-PostgresSql {
    param([string]$Sql)

    $env:PGPASSWORD = $DbPassword
    try {
        if (Test-Command "psql") {
            psql `
                -h $DbHost `
                -p $DbPort `
                -U $DbUser `
                -d $DbName `
                -v ON_ERROR_STOP=1 `
                -c $Sql
            return
        }

        if (Test-Command "docker") {
            $container = docker ps --filter "name=olympus-postgres" --format "{{.Names}}" 2>$null

            if ($container -eq "olympus-postgres") {
                docker exec `
                    -e PGPASSWORD=$DbPassword `
                    olympus-postgres `
                    psql `
                    -U $DbUser `
                    -d $DbName `
                    -v ON_ERROR_STOP=1 `
                    -c $Sql
                return
            }
        }

        Write-Fail "Could not run SQL. Install psql or run/start the olympus-postgres Docker container."
    } finally {
        Remove-Item Env:PGPASSWORD -ErrorAction SilentlyContinue
    }
}

function Test-PostgresTableExists {
    param([string]$TableName)

    $code = @"
import os
import sys

import psycopg

database_url = os.environ.get("DATABASE_URL") or os.environ.get("PSYCOPG_URL")
if not database_url:
    sys.exit(2)

with psycopg.connect(database_url) as conn:
    with conn.cursor() as cur:
        cur.execute("SELECT to_regclass(%s) IS NOT NULL", (f"public.{sys.argv[1]}",))
        print("1" if cur.fetchone()[0] else "0")
"@

    $result = $code | python - $TableName
    if ($LASTEXITCODE -ne 0) {
        Write-Warn "Could not inspect PostgreSQL table '$TableName'."
        return $false
    }

    return (($result | Select-Object -Last 1) -eq "1")
}

function Test-PostgresColumnExists {
    param(
        [string]$TableName,
        [string]$ColumnName
    )

    $code = @"
import os
import sys

import psycopg

database_url = os.environ.get("DATABASE_URL") or os.environ.get("PSYCOPG_URL")
if not database_url:
    sys.exit(2)

with psycopg.connect(database_url) as conn:
    with conn.cursor() as cur:
        cur.execute(
            """
            SELECT 1
            FROM information_schema.columns
            WHERE table_schema = 'public'
              AND table_name = %s
              AND column_name = %s
            """,
            (sys.argv[1], sys.argv[2]),
        )
        print("1" if cur.fetchone() else "0")
"@

    $result = $code | python - $TableName $ColumnName
    if ($LASTEXITCODE -ne 0) {
        Write-Warn "Could not inspect PostgreSQL column '$TableName.$ColumnName'."
        return $false
    }

    return (($result | Select-Object -Last 1) -eq "1")
}

function Invoke-AlembicStamp {
    param([string]$Revision)

    python -m alembic stamp $Revision

    if ($LASTEXITCODE -ne 0) {
        Write-Fail "Alembic stamp failed with exit code $LASTEXITCODE"
    }
}

function Invoke-AlembicUpgradeHeadWithRecovery {
    param([string]$RepoRoot)

    Push-Location $RepoRoot
    try {
        $stampedRevisions = @{}

        for ($attempt = 1; $attempt -le 8; $attempt++) {
            python -m alembic upgrade head
            $alembicExit = $LASTEXITCODE

            if ($alembicExit -eq 0) {
                return
            }

            $initialSchemaPresent = Test-PostgresTableExists -TableName "doc_commits"
            $alembicVersionPresent = Test-PostgresTableExists -TableName "alembic_version"
            $datasetArtifactsPresent = Test-PostgresTableExists -TableName "dataset_artifacts"
            $datasetArtifactFilesPresent = Test-PostgresTableExists -TableName "dataset_artifact_files"
            $datasetLineagePresent = Test-PostgresTableExists -TableName "dataset_lineage_events"
            $ledgerActivitiesPresent = Test-PostgresTableExists -TableName "ledger_activities"
            $rekorAnchorsPresent = Test-PostgresTableExists -TableName "rekor_anchors"
            $tsaJobsPresent = Test-PostgresTableExists -TableName "tsa_jobs"
            $apiKeysPresent = Test-PostgresTableExists -TableName "api_keys"
            $revocationCommitIdPresent = Test-PostgresColumnExists -TableName "key_credentials" -ColumnName "revocation_commit_id"
            $issuedByKeyIdPresent = Test-PostgresColumnExists -TableName "key_credentials" -ColumnName "issued_by_key_id"

            $revisionToStamp = ""
            $reason = ""

            if ($issuedByKeyIdPresent -and -not $stampedRevisions.ContainsKey("b1c2d3e4f5a6")) {
                $revisionToStamp = "b1c2d3e4f5a6"
                $reason = "key_credentials.issued_by_key_id column already exists"
            } elseif ($apiKeysPresent -and -not $stampedRevisions.ContainsKey("a1b2c3d4e5f7")) {
                $revisionToStamp = "a1b2c3d4e5f7"
                $reason = "api_keys table already exists"
            } elseif ($tsaJobsPresent -and -not $stampedRevisions.ContainsKey("f6a7b8c9d0e1")) {
                $revisionToStamp = "f6a7b8c9d0e1"
                $reason = "tsa_jobs table already exists"
            } elseif ($rekorAnchorsPresent -and -not $stampedRevisions.ContainsKey("e5f6a7b8c9d0")) {
                $revisionToStamp = "e5f6a7b8c9d0"
                $reason = "rekor_anchors table already exists"
            } elseif ($ledgerActivitiesPresent -and -not $stampedRevisions.ContainsKey("a9b8c7d6e5f4")) {
                $revisionToStamp = "a9b8c7d6e5f4"
                $reason = "ledger_activities table already exists"
            } elseif ($datasetArtifactsPresent -and $datasetArtifactFilesPresent -and $datasetLineagePresent -and -not $stampedRevisions.ContainsKey("a1b2c3d4e5f6")) {
                $revisionToStamp = "a1b2c3d4e5f6"
                $reason = "dataset provenance tables already exist"
            } elseif ($revocationCommitIdPresent -and -not $stampedRevisions.ContainsKey("8398af14bd26")) {
                $revisionToStamp = "8398af14bd26"
                $reason = "key_credentials.revocation_commit_id column already exists"
            } elseif ($initialSchemaPresent -and -not $alembicVersionPresent -and -not $stampedRevisions.ContainsKey("150ed68bf7cc")) {
                $revisionToStamp = "150ed68bf7cc"
                $reason = "existing Olympus initial tables without alembic_version"
            }

            if (-not $revisionToStamp) {
                Write-Fail "Alembic migration failed with exit code $alembicExit"
            }

            Write-Warn "Alembic hit pre-existing schema state: $reason."
            Write-Warn "Stamping revision $revisionToStamp, then retrying migrations."
            Invoke-AlembicStamp -Revision $revisionToStamp
            $stampedRevisions[$revisionToStamp] = $true
        }

        Write-Fail "Alembic migration recovery exceeded retry limit."
    } finally {
        Pop-Location
    }
}

function Test-RustToolchain {
    if (-not (Test-Command "cargo")) {
        Write-Fail "Rust/Cargo not found. Install Rust from https://rustup.rs/, then reopen PowerShell and rerun."
    }

    $cargoVersion = cargo --version 2>&1
    Write-Ok "$cargoVersion"
}

function Test-GoToolchain {
    if (-not (Test-Command "go")) {
        if ($RequireGoSequencer -or $BuildGoSequencer -or $TestGoSequencer -or $StartGoSequencer -or $RunSequencerSmokeTests) {
            Write-Fail "Go toolchain not found. Install Go, reopen PowerShell, and rerun."
        }

        Write-Warn "Go toolchain not found. Skipping Go sequencer setup."
        return $false
    }

    $goVersion = go version 2>&1
    Write-Ok "$goVersion"
    return $true
}

function Test-NodeToolchain {
    if (-not (Test-Command "node")) {
        Write-Fail "Node.js not found. Install Node.js 20.19+ or 22.12+, reopen PowerShell, and rerun. Use -SkipUi to skip UX setup."
    }

    if (-not (Test-Command "npm")) {
        Write-Fail "npm not found. Install Node.js with npm, reopen PowerShell, and rerun. Use -SkipUi to skip UX setup."
    }

    $nodeVersion = node --version 2>&1
    $npmVersion = npm --version 2>&1
    Write-Ok "node $nodeVersion"
    Write-Ok "npm $npmVersion"
}

function Install-PublicUiDeps {
    param([string]$UiDir)

    if (-not (Test-Path (Join-Path $UiDir "package.json"))) {
        Write-Warn "Public UX package.json not found at $UiDir. Skipping UX dependency install."
        return
    }

    Write-Step "Installing public UX dependencies"
    Stop-PublicUiServer -UiDir $UiDir

    $npmCmd = Get-Command "npm.cmd" -ErrorAction SilentlyContinue
    if (-not $npmCmd) {
        $npmCmd = Get-Command "npm" -ErrorAction SilentlyContinue
    }
    if (-not $npmCmd) {
        Write-Fail "npm not found. Install Node.js with npm, reopen PowerShell, and rerun. Use -SkipUi to skip UX setup."
    }

    $npmArgs = if (Test-Path (Join-Path $UiDir "package-lock.json")) {
        @("ci", "--legacy-peer-deps", "--no-audit", "--no-fund")
    } else {
        @("install", "--legacy-peer-deps", "--no-audit", "--no-fund")
    }

    for ($attempt = 1; $attempt -le 2; $attempt++) {
        $exitCode = 0

        if ($HideServerWindows) {
            $proc = Start-Process `
                -FilePath $npmCmd.Source `
                -ArgumentList $npmArgs `
                -WorkingDirectory $UiDir `
                -WindowStyle Hidden `
                -Wait `
                -PassThru
            $exitCode = $proc.ExitCode
        } else {
            Push-Location $UiDir
            try {
                & $npmCmd.Source @npmArgs
                $exitCode = $LASTEXITCODE
            } finally {
                Pop-Location
            }
        }

        if ($exitCode -eq 0) {
            Write-Ok "Public UX dependencies are installed."
            return
        }

        if ($attempt -eq 1 -and $exitCode -eq -4048) {
            Write-Warn "Public UX install hit a Windows file lock. Stopping stale UI processes and retrying."
            Stop-PublicUiServer -UiDir $UiDir
            Start-Sleep -Seconds 2
            continue
        }

        Write-Fail "Public UX dependency install failed with exit code $exitCode"
    }
}

function Ensure-PortablePostgres {
    param([string]$RepoRoot)

    $vendorDir = Join-Path $RepoRoot "vendor"
    $vendorPg  = Join-Path $vendorDir "pgsql"
    $pgCtl     = Join-Path $vendorPg  "bin\pg_ctl.exe"
    $pgReady   = Join-Path $vendorPg  "bin\pg_isready.exe"
    $psql      = Join-Path $vendorPg  "bin\psql.exe"
    $pgData    = Join-Path $vendorDir "pgdata"
    $pgZip     = Join-Path $vendorDir "pgsql.zip"

    # 1. Download and extract binaries (one-time, ~300 MB).
    if (-not (Test-Path $pgCtl)) {
        Write-Step "Downloading portable PostgreSQL 16 (~300 MB, one-time only) ..."
        New-Item -ItemType Directory -Force -Path $vendorDir | Out-Null

        try {
            Invoke-WebRequest -Uri $PortablePostgresUrl -OutFile $pgZip -UseBasicParsing
        } catch {
            Write-Fail "Failed to download portable PostgreSQL: $_`nCheck your internet connection or use -StartDocker instead."
        }

        Write-Ok "Extracting ..."
        Expand-Archive -Path $pgZip -DestinationPath $vendorDir -Force
        Remove-Item $pgZip -Force -ErrorAction SilentlyContinue

        if (-not (Test-Path $pgCtl)) {
            Write-Fail "Extraction succeeded but pg_ctl.exe not found at $pgCtl — check the zip layout."
        }
        Write-Ok "Portable PostgreSQL extracted to vendor\pgsql"
    } else {
        Write-Ok "Portable PostgreSQL already present at vendor\pgsql"
    }

    # 2. Initialise data directory (one-time).
    if (-not (Test-Path (Join-Path $pgData "PG_VERSION"))) {
        Write-Step "Initialising PostgreSQL data directory ..."
        New-Item -ItemType Directory -Force -Path $pgData | Out-Null
        $initArgs = "--auth=trust --username=$DbUser --encoding=UTF8"
        & $pgCtl initdb -D $pgData -o $initArgs | Out-Null
        if ($LASTEXITCODE -ne 0) {
            Write-Fail "pg_ctl initdb failed. Check vendor\pgdata for details."
        }
        Write-Ok "Data directory initialised at vendor\pgdata"
    }

    # 3. Start server if not already running.
    $pgStatus = & $pgCtl status -D $pgData 2>&1
    if ($pgStatus -notmatch "server is running") {
        if (Test-TcpPort -HostName "127.0.0.1" -Port $DbPort) {
            Write-Warn "Port $DbPort is already in use by another PostgreSQL instance."

            $env:PGPASSWORD = $DbPassword
            & $pgReady -h 127.0.0.1 -p $DbPort -U $DbUser -d $DbName 2>$null | Out-Null
            $readyExit = $LASTEXITCODE
            & $psql -h 127.0.0.1 -p $DbPort -U $DbUser -d $DbName -v ON_ERROR_STOP=1 -c "select 1" 2>$null | Out-Null
            $psqlExit = $LASTEXITCODE
            Remove-Item Env:PGPASSWORD -ErrorAction SilentlyContinue

            if ($readyExit -eq 0 -and $psqlExit -eq 0) {
                Write-Ok ("Using existing PostgreSQL on 127.0.0.1:{0} for database '{1}'." -f $DbPort, $DbName)
            } else {
                Write-Fail ("Port {0} is occupied, but Olympus could not connect as '{1}' to database '{2}'. Stop the other PostgreSQL service, create the database/user there, or rerun with a different -DbPort." -f $DbPort, $DbUser, $DbName)
            }
        } else {
            Write-Step "Starting portable PostgreSQL on port $DbPort ..."
            $pgLog = Join-Path $pgData "pg.log"
            # Bind to loopback only — no reason to expose the dev DB on all interfaces.
            & $pgCtl start -D $pgData -l $pgLog -o "-p $DbPort -c listen_addresses=127.0.0.1" | Out-Null
            if ($LASTEXITCODE -ne 0) {
                Write-Fail "pg_ctl start failed. See $pgLog for details."
            }
            Start-Sleep -Seconds 2

            # Create the application database.
            # Exit code 0 = created; exit code 1 = database already exists (both acceptable).
            # Any other non-zero exit code is a real error (permissions, bad host, etc.).
            $createDb = Join-Path $vendorPg "bin\createdb.exe"
            $env:PGPASSWORD = $DbPassword
            $createDbOutput = & $createDb -h 127.0.0.1 -p $DbPort -U $DbUser $DbName 2>&1
            $createDbExit = $LASTEXITCODE
            Remove-Item Env:PGPASSWORD -ErrorAction SilentlyContinue
            if ($createDbExit -ne 0 -and $createDbExit -ne 1) {
                Write-Fail "createdb.exe failed (exit $createDbExit): $createDbOutput"
            }
            if ($createDbExit -eq 1) {
                Write-Ok "Database '$DbName' already exists — skipping createdb."
            }
            Write-Ok "Portable PostgreSQL running on 127.0.0.1:$DbPort"
        }
    } else {
        Write-Ok "Portable PostgreSQL already running on port $DbPort"
    }

    # 4. Override DATABASE_URL to point at local PostgreSQL.
    $env:DATABASE_URL = "postgresql+asyncpg://" + $DbUser + ":" + $DbPassword + "@" + "127.0.0.1:" + $DbPort + "/" + $DbName
    $env:PSYCOPG_URL  = "postgresql://" + $DbUser + ":" + $DbPassword + "@" + "127.0.0.1:" + $DbPort + "/" + $DbName
    Set-DotEnvValue -Path (Join-Path $RepoRoot ".env") -Key "DATABASE_URL" -Value $env:DATABASE_URL
    Set-DotEnvValue -Path (Join-Path $RepoRoot ".env") -Key "PSYCOPG_URL"  -Value $env:PSYCOPG_URL
    Write-Ok "DATABASE_URL updated to portable instance."
}

function Stop-PublicUiServer {
    param([string]$UiDir)

    $resolvedUiDir = (Resolve-Path $UiDir).Path
    $escapedUiDir = [regex]::Escape($resolvedUiDir)
    $processes = @(
        Get-CimInstance Win32_Process -ErrorAction SilentlyContinue |
            Where-Object {
                $_.CommandLine -and
                (
                    $_.CommandLine -match $escapedUiDir -or
                    ($_.CommandLine -match "vite" -and $_.CommandLine -match "5173")
                )
            }
    )

    foreach ($process in $processes) {
        try {
            Stop-Process -Id $process.ProcessId -Force -ErrorAction SilentlyContinue
        } catch {
            # Best effort: stale dev servers should not block setup.
        }
    }

    if ($processes.Count -gt 0) {
        Write-Ok "Stopped stale public UX process(es): $($processes.ProcessId -join ', ')"
    }
}

function Open-BrowserUrl {
    param([string]$Url)

    if (-not $Url) {
        return
    }

    $browserCandidates = @(
        @{ Name = "msedge.exe"; Args = @("--new-window", $Url) },
        @{ Name = "chrome.exe"; Args = @("--new-window", $Url) },
        @{ Name = "firefox.exe"; Args = @("--new-window", $Url) }
    )

    foreach ($candidate in $browserCandidates) {
        $cmd = Get-Command $candidate.Name -ErrorAction SilentlyContinue
        if ($cmd) {
            Start-Process -FilePath $cmd.Source -ArgumentList $candidate.Args | Out-Null
            Write-Ok "Opened browser window: $Url"
            return
        }
    }

    Start-Process $Url | Out-Null
    Write-Ok "Opened browser URL: $Url"
}

function Close-LauncherSplash {
    # Close only the Olympus HTA splash, not random mshta windows.
    try {
        Get-CimInstance Win32_Process -Filter "Name = 'mshta.exe'" -ErrorAction SilentlyContinue |
            Where-Object { $_.CommandLine -like '*Olympus-Launcher.hta*' -or $_.CommandLine -like '*Olympus Local App*' } |
            ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }
    } catch {
        Get-Process mshta -ErrorAction SilentlyContinue |
            Where-Object { $_.MainWindowTitle -like '*Olympus*' } |
            Stop-Process -Force -ErrorAction SilentlyContinue
    }
}

function Start-PublicUiServer {
    param(
        [string]$UiDir,
        [int]$Port
    )

    Write-Step "Starting public UX"

    # If a pre-built dist/ exists, FastAPI serves it directly — no Vite needed.
    # Return the API URL so the caller opens the right browser tab.
    $distIndex = Join-Path $UiDir "dist\index.html"
    if (Test-Path $distIndex) {
        Write-Ok "Pre-built UI found at $UiDir\dist — served by FastAPI. Skipping Vite dev server."
        Write-Ok "UI will be available at http://localhost:8000 once the API starts."
        return "http://localhost:8000"
    }

    if (Test-TcpPort -HostName "127.0.0.1" -Port $Port) {
        Write-Ok "Public UX already appears reachable at http://localhost:$Port"
        return
    }

    $pwsh = Get-PowerShellHost

    $command = @(
        "cd '$UiDir'",
        "Remove-Item Env:\VITE_API_BASE -ErrorAction SilentlyContinue",
        "Remove-Item Env:\VITE_API_BASE_URL -ErrorAction SilentlyContinue",
        "npm run dev -- --host 127.0.0.1 --port $Port"
    ) -join "`n"

    $startArgs = @{}
    $startArgs["FilePath"] = $pwsh
    $startArgs["ArgumentList"] = @("-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", $command)
    if ($HideServerWindows) {
        $startArgs.WindowStyle = "Hidden"
    }

    Start-Process @startArgs | Out-Null

    for ($i = 0; $i -lt 20; $i++) {
        Start-Sleep -Milliseconds 500

        if (Test-TcpPort -HostName "127.0.0.1" -Port $Port) {
            Write-Ok "Public UX is listening at http://localhost:$Port"
            return
        }
    }

    Write-Warn "Public UX process started, but http://localhost:$Port was not reachable yet."
}

function Find-GoSequencerDirs {
    param([string]$Root)

    $goMods = Get-ChildItem -Path $Root -Recurse -Force -Filter "go.mod" |
        Where-Object {
            $_.FullName -notmatch "\\.venv\\" -and
            $_.FullName -notmatch "\\node_modules\\" -and
            $_.FullName -notmatch "\\target\\" -and
            $_.FullName -notmatch "\\.git\\"
        }

    $candidates = @()

    foreach ($goMod in $goMods) {
        $dir = Split-Path $goMod.FullName -Parent
        $dirName = Split-Path $dir -Leaf
        $goModText = Get-Content $goMod.FullName -Raw

        if (
            $dirName -match "sequencer" -or
            $goMod.FullName -match "sequencer" -or
            $goModText -match "sequencer"
        ) {
            $candidates += $dir
        }
    }

    return $candidates | Select-Object -Unique
}

function New-GoSequencerTokenIfMissing {
    param([string]$EnvPath)

    if (-not $env:OLYMPUS_SEQUENCER_TOKEN) {
        $token = New-RandomHexKey
        $env:OLYMPUS_SEQUENCER_TOKEN = $token
        Set-DotEnvValue -Path $EnvPath -Key "OLYMPUS_SEQUENCER_TOKEN" -Value $token
        Write-Ok "OLYMPUS_SEQUENCER_TOKEN generated and written to .env."
    } else {
        Write-Ok "OLYMPUS_SEQUENCER_TOKEN loaded."
    }

    $env:SEQUENCER_API_TOKEN = $env:OLYMPUS_SEQUENCER_TOKEN
    Set-DotEnvValue -Path $EnvPath -Key "SEQUENCER_API_TOKEN" -Value $env:SEQUENCER_API_TOKEN
}

function Normalize-IntegerEnv {
    param(
        [string]$EnvPath,
        [string]$Key,
        [string]$DefaultValue
    )

    $current = [Environment]::GetEnvironmentVariable($Key, "Process")

    if (-not $current) {
        $current = $DefaultValue
    }

    $clean = ($current -split '#', 2)[0].Trim()

    if ($clean -notmatch '^\d+$') {
        Write-Warn "$Key had invalid value '$current'. Resetting to $DefaultValue."
        $clean = $DefaultValue
    }

    [Environment]::SetEnvironmentVariable($Key, $clean, "Process")
    Set-DotEnvValue -Path $EnvPath -Key $Key -Value $clean

    Write-Ok "$Key set to $clean"
}

function Clear-PipTempJunk {
    param([string]$RepoRoot)

    $sitePackages = Join-Path $RepoRoot ".venv\Lib\site-packages"

    if (-not (Test-Path $sitePackages)) {
        return
    }

    $junk = Get-ChildItem $sitePackages -Directory -Force -ErrorAction SilentlyContinue |
        Where-Object {
            $_.Name -like "~*" -or
            $_.Name -like "*.tmp" -or
            $_.Name -like "pip-build-tracker-*" -or
            $_.Name -like "pip-unpack-*"
        }

    foreach ($item in $junk) {
        try {
            Remove-Item $item.FullName -Recurse -Force -ErrorAction Stop
            Write-Ok "Removed stale pip temp directory: $($item.Name)"
        } catch {
            Write-Warn "Could not remove stale pip temp directory: $($item.FullName)"
        }
    }
}

function Invoke-WindowsFirstBoot {
    param([string]$RepoRoot)

    if ($SkipFirstBoot) {
        Write-Ok "Skipping Windows first-boot bootstrap."
        return
    }

    $bootstrapScript = Join-Path $RepoRoot "scripts\bootstrap.ps1"

    if (-not (Test-Path $bootstrapScript)) {
        Write-Warn "Windows first-boot helper not found at $bootstrapScript. Continuing."
        return
    }

    Write-Step "Running Windows first-boot bootstrap"

    $pwsh = Get-PowerShellHost
    & $pwsh -NoProfile -ExecutionPolicy Bypass -File $bootstrapScript

    if ($LASTEXITCODE -ne 0) {
        Write-Fail "Windows first-boot bootstrap failed with exit code $LASTEXITCODE"
    }

    Write-Ok "Windows first-boot bootstrap complete."
}

function Clear-SequencerDbEnv {
    param([string]$EnvPath)

    $keys = @(
        "SEQUENCER_DB_URL",
        "SEQUENCER_DB_HOST",
        "SEQUENCER_DB_PORT",
        "SEQUENCER_DB_USER",
        "SEQUENCER_DB_PASSWORD",
        "SEQUENCER_DB_PASSWORD_FILE",
        "SEQUENCER_DB_NAME",
        "SEQUENCER_DB_SSLMODE"
    )

    foreach ($key in $keys) {
        Remove-Item "Env:$key" -ErrorAction SilentlyContinue
        Remove-DotEnvKey -Path $EnvPath -Key $key
    }
}

function Configure-GoSequencerDbEnv {
    param(
        [string]$EnvPath,
        [string]$Mode
    )

    Write-Step "Configuring Go sequencer DB environment"

    Clear-SequencerDbEnv -EnvPath $EnvPath

    $env:SEQUENCER_ALLOW_INSECURE_DB = "1"
    Set-DotEnvValue -Path $EnvPath -Key "SEQUENCER_ALLOW_INSECURE_DB" -Value "1"
    Write-Warn "SEQUENCER_ALLOW_INSECURE_DB=1 set for local development only."

    if ($Mode -eq "url") {
        $seqDbUrl = "postgresql://${DbUser}:${DbPassword}@${DbHost}:${DbPort}/${DbName}?sslmode=disable"

        $env:SEQUENCER_DB_URL = $seqDbUrl
        Set-DotEnvValue -Path $EnvPath -Key "SEQUENCER_DB_URL" -Value $seqDbUrl

        Write-Ok "SEQUENCER_DB_URL set to $(Mask-DatabaseUrl $seqDbUrl)"
        Write-Ok "Sequencer DB mode: url"
        return
    }

    $env:SEQUENCER_DB_HOST = $DbHost
    $env:SEQUENCER_DB_PORT = "$DbPort"
    $env:SEQUENCER_DB_USER = $DbUser
    $env:SEQUENCER_DB_PASSWORD = $DbPassword
    $env:SEQUENCER_DB_NAME = $DbName
    $env:SEQUENCER_DB_SSLMODE = "disable"

    Set-DotEnvValue -Path $EnvPath -Key "SEQUENCER_DB_HOST" -Value $env:SEQUENCER_DB_HOST
    Set-DotEnvValue -Path $EnvPath -Key "SEQUENCER_DB_PORT" -Value $env:SEQUENCER_DB_PORT
    Set-DotEnvValue -Path $EnvPath -Key "SEQUENCER_DB_USER" -Value $env:SEQUENCER_DB_USER
    Set-DotEnvValue -Path $EnvPath -Key "SEQUENCER_DB_PASSWORD" -Value $env:SEQUENCER_DB_PASSWORD
    Set-DotEnvValue -Path $EnvPath -Key "SEQUENCER_DB_NAME" -Value $env:SEQUENCER_DB_NAME
    Set-DotEnvValue -Path $EnvPath -Key "SEQUENCER_DB_SSLMODE" -Value $env:SEQUENCER_DB_SSLMODE

    Write-Ok "Sequencer component DB vars set."
    Write-Ok "Sequencer DB mode: components"
}

function Test-WslAvailable {
    if (-not (Test-Command "wsl.exe")) {
        Write-Fail "wsl.exe not found. Install WSL first: wsl --install"
    }

    $list = wsl.exe -l -q 2>$null
    if ($LASTEXITCODE -ne 0 -or -not $list) {
        Write-Fail "WSL is installed but no distro appears available. Run: wsl --install -d Ubuntu"
    }

    Write-Ok "WSL available."
}

function Convert-ToWslPath {
    param([string]$WindowsPath)

    if ($WslRepoPath -and $WindowsPath -eq $RepoRoot) {
        return $WslRepoPath
    }

    $escaped = $WindowsPath.Replace("\", "\\").Replace("'", "'\''")
    $cmd = "wslpath -a '$escaped'"

    if ($WslDistro) {
        $path = wsl.exe -d $WslDistro -- bash -lc $cmd
    } else {
        $path = wsl.exe -- bash -lc $cmd
    }

    if ($LASTEXITCODE -ne 0 -or -not $path) {
        Write-Fail "Could not convert Windows path '$WindowsPath' to WSL path. Pass -WslRepoPath manually if converting repo root."
    }

    return ($path | Select-Object -First 1).Trim()
}

function Invoke-WslCommand {
    param(
        [string]$Command,
        [switch]$IgnoreExitCode
    )

    $safeTitle = "inline"
    $scriptName = ".olympus-wsl-$safeTitle-$([Guid]::NewGuid().ToString('N')).sh"
    $scriptPath = Join-Path $RepoRoot $scriptName

    $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllText($scriptPath, $Command.Replace("`r`n", "`n"), $utf8NoBom)

    $wslScriptPath = Convert-ToWslPath -WindowsPath $scriptPath

    if ($WslDistro) {
        wsl.exe -d $WslDistro -- bash $wslScriptPath
    } else {
        wsl.exe -- bash $wslScriptPath
    }

    $exit = $LASTEXITCODE

    Remove-Item $scriptPath -Force -ErrorAction SilentlyContinue

    if (-not $IgnoreExitCode -and $exit -ne 0) {
        Write-Fail "WSL command failed with exit code $exit"
    }
}

function Get-WslDbHost {
    if ($WslDbHost -and $WslDbHost -ne "auto") {
        return $WslDbHost
    }

    $cmd = "awk '/^nameserver/ { print `$2; exit }' /etc/resolv.conf"

    if ($WslDistro) {
        $raw = wsl.exe -d $WslDistro -- bash -lc $cmd
    } else {
        $raw = wsl.exe -- bash -lc $cmd
    }

    if ($LASTEXITCODE -ne 0 -or -not $raw) {
        Write-Warn "Could not auto-detect Windows host IP from WSL. Falling back to 127.0.0.1."
        return "127.0.0.1"
    }

    $line = ($raw | Select-Object -First 1).Trim()

    if ($line -match '(\d{1,3}(\.\d{1,3}){3})') {
        return $Matches[1]
    }

    Write-Warn "Could not parse WSL nameserver from '$line'. Falling back to 127.0.0.1."
    return "127.0.0.1"
}

function Get-WslVmIp {
    $cmd = "hostname -I | awk '{ print `$1; exit }'"

    if ($WslDistro) {
        $raw = wsl.exe -d $WslDistro -- bash -lc $cmd
    } else {
        $raw = wsl.exe -- bash -lc $cmd
    }

    if ($LASTEXITCODE -ne 0 -or -not $raw) {
        Write-Warn "Could not auto-detect WSL VM IP. Falling back to localhost for sequencer URL."
        return ""
    }

    $line = ($raw | Select-Object -First 1).Trim()

    if ($line -match '(\d{1,3}(\.\d{1,3}){3})') {
        return $Matches[1]
    }

    Write-Warn "Could not parse WSL VM IP from '$line'. Falling back to localhost for sequencer URL."
    return ""
}

function Start-WslWindow {
    param(
        [string]$Title,
        [string]$Command
    )

    $pwsh = Get-PowerShellHost

    $safeTitle = ($Title -replace '[^a-zA-Z0-9_-]', '_')
    $scriptName = "olympus-wsl-$safeTitle-$([Guid]::NewGuid().ToString('N')).sh"
    # Write to the system temp directory so credentials embedded in the script
    # are never placed inside the repo tree (prevents accidental commits and
    # reduces the window during which secrets sit on a predictable path).
    $scriptPath = Join-Path ([System.IO.Path]::GetTempPath()) $scriptName

    $logRoot = Join-Path $RepoRoot ".olympus-logs"
    New-Item -ItemType Directory -Force -Path $logRoot | Out-Null
    $logPath = Join-Path $logRoot ("$scriptName.log")
    $wslLogPath = Convert-ToWslPath -WindowsPath $logPath

    # Prepend a self-delete trap so the script removes itself after execution,
    # minimising the time credentials are stored on disk. Also tee output to a log
    # so hidden WSL windows still leave a useful failure trail.
    $selfDeleteTemplate = @'
exec > >(tee -a '{0}') 2>&1
trap 'rm -f "$0"' EXIT
'@
    $selfDelete = $selfDeleteTemplate -f $wslLogPath
    $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllText($scriptPath, ($selfDelete + $Command).Replace("`r`n", "`n"), $utf8NoBom)

    $wslScriptPath = Convert-ToWslPath -WindowsPath $scriptPath

    if ($WslDistro) {
        $psCommand = "Write-Host '$Title' -ForegroundColor Cyan; wsl.exe -d '$WslDistro' -- bash '$wslScriptPath'"
    } else {
        $psCommand = "Write-Host '$Title' -ForegroundColor Cyan; wsl.exe -- bash '$wslScriptPath'"
    }

    $startArgs = @{}
    $startArgs["FilePath"] = $pwsh
    $startArgs["ArgumentList"] = @("-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", $psCommand)
    if ($HideServerWindows) {
        $startArgs.WindowStyle = "Hidden"
    }

    Start-Process @startArgs | Out-Null
}

function Wait-WslSocket {
    param(
        [string]$SocketPath,
        [int]$TimeoutSeconds = 60
    )

    Write-Step "Waiting for WSL socket $SocketPath"

    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)

    while ((Get-Date) -lt $deadline) {
        $testCmd = "test -S '$SocketPath'"

        if ($WslDistro) {
            wsl.exe -d $WslDistro -- bash -lc $testCmd | Out-Null
        } else {
            wsl.exe -- bash -lc $testCmd | Out-Null
        }

        if ($LASTEXITCODE -eq 0) {
            Write-Ok "WSL socket is ready: $SocketPath"
            return
        }

        Start-Sleep -Milliseconds 500
    }

    $logDir = Join-Path $RepoRoot ".olympus-logs"
    $latestLog = Get-ChildItem $logDir -Filter "olympus-wsl-*CDHS*.log" -ErrorAction SilentlyContinue |
        Sort-Object LastWriteTime -Descending |
        Select-Object -First 1
    if ($latestLog) {
        Write-Warn "Latest CDHS-SMF log: $($latestLog.FullName)"
        Write-Warn "Last 40 log lines:"
        Get-Content $latestLog.FullName -Tail 40 -ErrorAction SilentlyContinue | ForEach-Object { Write-Host "    $_" -ForegroundColor DarkGray }
    }
    throw "Timed out waiting for WSL socket: $SocketPath"
}

function Start-WslCdhsSmfServer {
    param(
        [string]$WslRepo,
        [string]$SocketPath
    )

    Write-Step "Starting CDHS-SMF under WSL"

    $cmd = @(
        "set -e",
        "mkdir -p /run/olympus 2`>/dev/null `|`| sudo -n mkdir -p /run/olympus 2`>/dev/null `|`| sudo mkdir -p /run/olympus",
        "chmod 777 /run/olympus 2`>/dev/null `|`| sudo -n chmod 777 /run/olympus 2`>/dev/null `|`| sudo chmod 777 /run/olympus",
        "secret_dir=`"`$HOME/.config/olympus/secrets`"",
        "secret_key=`"`$secret_dir/sequencer-smt.key`"",
        "mkdir -p `"`$secret_dir`"",
        "chmod 700 `"`$secret_dir`"",
        "if [ ! -f `"`$secret_key`" ]; then",
        "  openssl rand -hex 32 > `"`$secret_key`"",
        "fi",
        "chmod 600 `"`$secret_key`"",
        "cd '$WslRepo/services/cdhs-smf-rust'",
        "export CDHS_SMF_SOCKET='$SocketPath'",
        "export CDHS_SMF_UNLINK_STALE_SOCKET=1",
        "export SEQUENCER_SMT_SIGNING_KEY_PATH=`"`$secret_key`"",
        "export CARGO_TARGET_DIR=/tmp/olympus-cargo-target",
        "[ -f `"`$HOME/.cargo/env`" ] `&`& . `"`$HOME/.cargo/env`"",
        "echo '[cdhs-smf] socket=$SocketPath'",
        "echo `"[cdhs-smf] signing_key_path=`$secret_key`"",
        "cargo --version",
        "cargo run"
    ) -join "`n"

    Start-WslWindow -Title "Olympus CDHS-SMF WSL server" -Command $cmd
    if ($HideServerWindows) {
        Write-Warn "Started WSL CDHS-SMF in a hidden PowerShell process."
    } else {
        Write-Warn "Opened WSL CDHS-SMF window. Leave it open."
    }
}

function Start-WslGoSequencerServer {
    param(
        [string]$WslRepo,
        [string]$SocketPath,
        [string]$HttpAddr,
        [string]$DbHostForWsl
    )

    Write-Step "Starting Go sequencer under WSL"

    $wslDbUrl = "postgresql://${DbUser}:${DbPassword}@${DbHostForWsl}:${DbPort}/${DbName}?sslmode=disable"

    $cmd = @(
        "set -e",
        "deadline=`$((SECONDS + 60))",
        "while [ ! -S '$SocketPath' ]; do",
        "  if [ `"`$SECONDS`" -ge `"`$deadline`" ]; then",
        "    echo '[sequencer] timed out waiting for CDHS-SMF socket: $SocketPath' `>`&2",
        "    exit 1",
        "  fi",
        "  echo '[sequencer] waiting for CDHS-SMF socket: $SocketPath'",
        "  sleep 0.5",
        "done",
        "cd '$WslRepo/services/sequencer-go'",
        "export SEQUENCER_ALLOW_INSECURE_DB=1",
        "export SEQUENCER_DB_URL='$wslDbUrl'",
        "export SEQUENCER_HTTP_ADDR='$HttpAddr'",
        "export CDHS_SMF_SOCKET='$SocketPath'",
        "export OLYMPUS_SEQUENCER_TOKEN='$env:OLYMPUS_SEQUENCER_TOKEN'",
        "export SEQUENCER_API_TOKEN='$env:SEQUENCER_API_TOKEN'",
        "[ -f `"`$HOME/.cargo/env`" ] `&`& . `"`$HOME/.cargo/env`"",
        "echo '[sequencer] db=postgresql://${DbUser}:***@${DbHostForWsl}:${DbPort}/${DbName}?sslmode=disable'",
        "echo '[sequencer] http=$HttpAddr'",
        "echo '[sequencer] cdhs=$SocketPath'",
        "go version",
        "go run ./cmd/sequencer"
    ) -join "`n"

    Start-WslWindow -Title "Olympus Go sequencer WSL server" -Command $cmd
    if ($HideServerWindows) {
        Write-Warn "Started WSL Go sequencer in a hidden PowerShell process."
    } else {
        Write-Warn "Opened WSL Go sequencer window. Leave it open."
    }
}

function Start-GoSequencerServer {
    param(
        [string]$SequencerDir,
        [string]$Addr,
        [string]$DbMode = "url"   # "url" or "components"
    )

    Write-Step "Starting native Windows Go sequencer server"

    $addrInfo = Get-HostAndPortFromAddr -Addr $Addr
    $listenHost = $addrInfo.Host
    $listenPort = $addrInfo.Port

    if (Test-TcpPort -HostName $listenHost -Port $listenPort) {
        Write-Ok "Go sequencer already appears reachable at $Addr"
        return
    }

    $pwsh = Get-PowerShellHost

    # Build the DB env block for the child process depending on mode.
    # "components" mode: forward the SEQUENCER_DB_* variables set by
    #   Configure-GoSequencerDbEnv; do NOT set SEQUENCER_DB_URL.
    # "url" mode: forward only SEQUENCER_DB_URL.
    $dbEnvLines = @("Get-ChildItem Env:SEQUENCER_DB* | Remove-Item -ErrorAction SilentlyContinue")
    if ($DbMode -eq "components") {
        $dbEnvLines += "`$env:SEQUENCER_DB_HOST='$env:SEQUENCER_DB_HOST'"
        $dbEnvLines += "`$env:SEQUENCER_DB_PORT='$env:SEQUENCER_DB_PORT'"
        $dbEnvLines += "`$env:SEQUENCER_DB_USER='$env:SEQUENCER_DB_USER'"
        $dbEnvLines += "`$env:SEQUENCER_DB_PASSWORD='$env:SEQUENCER_DB_PASSWORD'"
        $dbEnvLines += "`$env:SEQUENCER_DB_NAME='$env:SEQUENCER_DB_NAME'"
        $dbEnvLines += "`$env:SEQUENCER_DB_SSLMODE='$env:SEQUENCER_DB_SSLMODE'"
    } else {
        $dbEnvLines += "`$env:SEQUENCER_DB_URL='$env:SEQUENCER_DB_URL'"
    }

    $command = @(
        "cd '$SequencerDir'"
    ) + $dbEnvLines + @(
        "`$env:SEQUENCER_ALLOW_INSECURE_DB='1'",
        "`$env:SEQUENCER_HTTP_ADDR='$Addr'",
        "`$env:OLYMPUS_SEQUENCER_TOKEN='$env:OLYMPUS_SEQUENCER_TOKEN'",
        "`$env:SEQUENCER_API_TOKEN='$env:SEQUENCER_API_TOKEN'",
        "go run .\cmd\sequencer"
    ) -join "`n"

    Write-Warn "Starting native Windows Go sequencer. This may fail if CDHS-SMF Unix socket is required."
    $startArgs = @{}
    $startArgs["FilePath"] = $pwsh
    $startArgs["ArgumentList"] = @("-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", $command)
    if ($HideServerWindows) {
        $startArgs.WindowStyle = "Hidden"
    }

    Start-Process @startArgs | Out-Null

    $ready = $false

    for ($i = 0; $i -lt 15; $i++) {
        Start-Sleep -Seconds 1

        if (Test-TcpPort -HostName $listenHost -Port $listenPort) {
            $ready = $true
            break
        }
    }

    if ($ready) {
        Write-Ok "Go sequencer is listening at $Addr"
    } else {
        Write-Warn "Go sequencer did not start listening at $Addr. Native Windows likely hit CDHS-SMF Unix socket dependency."
    }
}

function Run-SequencerSmokeTests {
    param([string]$RepoRoot)

    Write-Step "Running Go sequencer live smoke tests"

    $env:GO_SEQUENCER_URL = $SequencerUrl
    $env:OLYMPUS_USE_GO_SEQUENCER = "1"
    $env:SEQUENCER_API_TOKEN = $env:OLYMPUS_SEQUENCER_TOKEN
    $env:MAX_UPLOAD_BYTES = "268435456"

    $addrInfo = Get-HostAndPortFromAddr -Addr "127.0.0.1:8081"

    if (-not (Test-TcpPort -HostName $addrInfo.Host -Port $addrInfo.Port)) {
        Write-Fail "Sequencer is not listening at 127.0.0.1:8081. Start WSL sequencer/CDHS first."
    }

    Push-Location $RepoRoot
    try {
        python -m pytest tests\test_sequencer_client_smoke.py -vv --tb=short

        if ($LASTEXITCODE -ne 0) {
            Write-Fail "Go sequencer smoke tests failed with exit code $LASTEXITCODE"
        }
    } finally {
        Pop-Location
    }

    Write-Ok "Go sequencer smoke tests passed."
}

# ---------------------------------------------------------------------------
# Banner
# ---------------------------------------------------------------------------

Write-Host ""
Write-Host "==================================================" -ForegroundColor Cyan
Write-Host "   Olympus -- dev-safe Windows setup + WSL       " -ForegroundColor Cyan
Write-Host "==================================================" -ForegroundColor Cyan

$RepoRoot = $PSScriptRoot
if (-not $RepoRoot) {
    $RepoRoot = (Get-Location).Path
}
$envFile = Join-Path $RepoRoot ".env"
$publicUiDir = Join-Path $RepoRoot "app\public-ui"

# Normalize $DbHost early so every subsequent section (incl. Go sequencer
# env config in section 3) uses the correct host.  The portable-postgres
# section also sets $DbHost = "127.0.0.1", but that comes after the
# sequencer section would otherwise have already written the wrong value.
if ($UsePortablePostgres) {
    $DbHost = "127.0.0.1"
}

# ---------------------------------------------------------------------------
# 1. First boot
# ---------------------------------------------------------------------------

Invoke-WindowsFirstBoot -RepoRoot $RepoRoot

# ---------------------------------------------------------------------------
# 2. Prerequisites
# ---------------------------------------------------------------------------

Write-Step "Checking prerequisites"

if (-not (Test-Command "python")) {
    Write-Fail "Python not found. Install Python 3.10+ and rerun."
}

$pyRaw = python --version 2>&1
if ($pyRaw -notmatch '3\.(1[0-9]|[2-9]\d)') {
    Write-Fail "Python 3.10+ is required. Found: $pyRaw"
}
Write-Ok "$pyRaw"

if ($StartDocker -and -not $SkipDocker) {
    Ensure-DockerDesktopRunning
}

if (-not $SkipRustBuild) {
    Test-RustToolchain
}

if (-not $SkipUi) {
    Test-NodeToolchain
}

if ($UseWslSequencer -or $StartWslCdhsSmf -or $StartWslGoSequencer) {
    Test-WslAvailable
}

# ---------------------------------------------------------------------------
# 3. Load environment
# ---------------------------------------------------------------------------

Write-Step "Loading environment"

Load-DotEnv -Path $envFile

# In DockerMode, override host references to use Docker Compose service names
if ($DockerMode) {
    $DbHost = "db"
    $SequencerUrl = "http://sequencer-go:8081"
    $SequencerHttpAddr = "sequencer-go:8081"
    Write-Ok "DockerMode: DbHost=db, SequencerUrl=http://sequencer-go:8081"
}

$localDbUrl = "postgresql://${DbUser}:${DbPassword}@${DbHost}:${DbPort}/${DbName}"

if ($ForceLocalDbUrl) {
    $env:DATABASE_URL = $localDbUrl
    $env:PSYCOPG_URL = $localDbUrl

    Set-DotEnvValue -Path $envFile -Key "DATABASE_URL" -Value $localDbUrl
    Set-DotEnvValue -Path $envFile -Key "PSYCOPG_URL" -Value $localDbUrl

    Write-Ok "DATABASE_URL forced to $(Mask-DatabaseUrl $localDbUrl)"
    Write-Ok "PSYCOPG_URL forced to $(Mask-DatabaseUrl $localDbUrl)"
} elseif ($env:DATABASE_URL -match "@db:") {
    # Already using Docker Compose service name — do not overwrite with a host IP
    Write-Ok "DATABASE_URL already uses Docker service name (db) — not overwriting."
} elseif (-not $env:DATABASE_URL) {
    $env:DATABASE_URL = $localDbUrl
    Write-Ok "DATABASE_URL set to $(Mask-DatabaseUrl $localDbUrl)"
} else {
    Write-Ok "DATABASE_URL already set -- using existing value: $(Mask-DatabaseUrl $env:DATABASE_URL)"
}

if (-not $env:PSYCOPG_URL) {
    $env:PSYCOPG_URL = $localDbUrl
    Write-Ok "PSYCOPG_URL set to $(Mask-DatabaseUrl $localDbUrl)"
}

Normalize-IntegerEnv -EnvPath $envFile -Key "MAX_UPLOAD_BYTES" -DefaultValue "268435456"

if (-not $env:OLYMPUS_DEV_SIGNING_KEY) {
    $env:OLYMPUS_DEV_SIGNING_KEY = "false"
    Set-DotEnvValue -Path $envFile -Key "OLYMPUS_DEV_SIGNING_KEY" -Value "false"
    Write-Ok "OLYMPUS_DEV_SIGNING_KEY set to false."
} else {
    Write-Ok "OLYMPUS_DEV_SIGNING_KEY already set to $env:OLYMPUS_DEV_SIGNING_KEY"
}

if (-not $env:OLYMPUS_INGEST_SIGNING_KEY) {
    $env:OLYMPUS_INGEST_SIGNING_KEY = New-RandomHexKey
    Set-DotEnvValue -Path $envFile -Key "OLYMPUS_INGEST_SIGNING_KEY" -Value $env:OLYMPUS_INGEST_SIGNING_KEY

    Write-Warn "OLYMPUS_INGEST_SIGNING_KEY was missing, so a dev key was generated."
    Write-Warn "This key was written to .env so signatures stay stable across restarts."
} else {
    Write-Ok "OLYMPUS_INGEST_SIGNING_KEY loaded."
}

if (-not $env:OLYMPUS_ADMIN_KEY) {
    $env:OLYMPUS_ADMIN_KEY = New-RandomHexKey
    Set-DotEnvValue -Path $envFile -Key "OLYMPUS_ADMIN_KEY" -Value $env:OLYMPUS_ADMIN_KEY
    Write-Warn "OLYMPUS_ADMIN_KEY was missing, so a local admin key was generated."
    Write-Warn "Use this key in the Admin page to create users and assign access."
} else {
    Write-Ok "OLYMPUS_ADMIN_KEY loaded."
}

if (-not $env:OLYMPUS_ALLOW_PUBLIC_WRITE_REGISTRATION) {
    $env:OLYMPUS_ALLOW_PUBLIC_WRITE_REGISTRATION = "1"
    Set-DotEnvValue -Path $envFile -Key "OLYMPUS_ALLOW_PUBLIC_WRITE_REGISTRATION" -Value "1"
    Write-Warn "OLYMPUS_ALLOW_PUBLIC_WRITE_REGISTRATION=1 enabled for local onboarding."
} else {
    Write-Ok "OLYMPUS_ALLOW_PUBLIC_WRITE_REGISTRATION already set to $env:OLYMPUS_ALLOW_PUBLIC_WRITE_REGISTRATION"
}

if (-not $env:OLYMPUS_REGISTER_RATE_LIMIT_MINUTE_CAPACITY) {
    $env:OLYMPUS_REGISTER_RATE_LIMIT_MINUTE_CAPACITY = "10"
    Set-DotEnvValue -Path $envFile -Key "OLYMPUS_REGISTER_RATE_LIMIT_MINUTE_CAPACITY" -Value "10"
    Write-Warn "OLYMPUS_REGISTER_RATE_LIMIT_MINUTE_CAPACITY=10 set for local onboarding."
} else {
    Write-Ok "OLYMPUS_REGISTER_RATE_LIMIT_MINUTE_CAPACITY already set to $env:OLYMPUS_REGISTER_RATE_LIMIT_MINUTE_CAPACITY"
}

$localCorsOrigins = "http://localhost:$UiPort,http://127.0.0.1:$UiPort,http://localhost:8000,http://127.0.0.1:8000,http://localhost:8080,http://127.0.0.1:8080"
if (-not $env:CORS_ORIGINS -or $env:CORS_ORIGINS -match "yourdomain") {
    $env:CORS_ORIGINS = $localCorsOrigins
    Set-DotEnvValue -Path $envFile -Key "CORS_ORIGINS" -Value $localCorsOrigins
    Write-Warn "CORS_ORIGINS set for local Windows UI/API development."
} else {
    Write-Ok "CORS_ORIGINS already set to $env:CORS_ORIGINS"
}

if (-not $SkipGoSequencer) {
    if ($EnableGoSequencer) {
        $env:OLYMPUS_USE_GO_SEQUENCER = "1"
        Set-DotEnvValue -Path $envFile -Key "OLYMPUS_USE_GO_SEQUENCER" -Value "1"
        Write-Ok "OLYMPUS_USE_GO_SEQUENCER enabled."
    } elseif (-not $env:OLYMPUS_USE_GO_SEQUENCER) {
        $env:OLYMPUS_USE_GO_SEQUENCER = "0"
        Set-DotEnvValue -Path $envFile -Key "OLYMPUS_USE_GO_SEQUENCER" -Value "0"
        Write-Ok "OLYMPUS_USE_GO_SEQUENCER defaulted to 0."
    } else {
        Write-Ok "OLYMPUS_USE_GO_SEQUENCER already set to $env:OLYMPUS_USE_GO_SEQUENCER"
    }

    New-GoSequencerTokenIfMissing -EnvPath $envFile

    if ($UseWslSequencer -and $SequencerUrl -eq "http://localhost:8081") {
        $wslSequencerAddrInfo = Get-HostAndPortFromAddr -Addr $WslSequencerHttpAddr
        $wslVmIp = Get-WslVmIp

        if ($wslVmIp) {
            $SequencerUrl = "http://${wslVmIp}:$($wslSequencerAddrInfo.Port)"
            Write-Ok "WSL sequencer URL set to $SequencerUrl"
        }
    }

    $env:GO_SEQUENCER_URL = $SequencerUrl
    $env:SEQUENCER_HTTP_ADDR = $SequencerHttpAddr

    # Only write sequencer URLs back to .env when NOT using Docker service names.
    # Docker Compose injects sequencer-go:8081 via the environment block in docker-compose.yml;
    # writing a host IP here would override that and break container-to-container routing.
    $currentSeqUrl = (Get-Content $envFile | Select-String "^GO_SEQUENCER_URL=").Line
    if ($currentSeqUrl -notmatch "sequencer-go") {
        Set-DotEnvValue -Path $envFile -Key "GO_SEQUENCER_URL" -Value $env:GO_SEQUENCER_URL
        Set-DotEnvValue -Path $envFile -Key "OLYMPUS_SEQUENCER_URL" -Value $env:GO_SEQUENCER_URL
        Set-DotEnvValue -Path $envFile -Key "SEQUENCER_HTTP_ADDR" -Value $env:SEQUENCER_HTTP_ADDR
    } else {
        Write-Ok "Sequencer URLs already use Docker service name (sequencer-go) — not overwriting."
    }

    Configure-GoSequencerDbEnv -EnvPath $envFile -Mode $SequencerDbMode
} else {
    Write-Warn "Skipping Go sequencer environment setup."
}

Save-DotEnvIfMissing -Path $envFile

# ---------------------------------------------------------------------------
# 4. PostgreSQL
# ---------------------------------------------------------------------------

Write-Step "Checking PostgreSQL"

if ($UsePortablePostgres) {
    Ensure-PortablePostgres -RepoRoot $RepoRoot
    $DbHost = "127.0.0.1"
}

$dbReachable = Test-TcpPort -HostName $DbHost -Port $DbPort

if ($dbReachable) {
    Write-Ok "PostgreSQL is reachable at ${DbHost}:${DbPort}"
} elseif ($StartDocker -and -not $SkipDocker) {
    Write-Warn "PostgreSQL not reachable. Starting standalone Docker Postgres."

    $running = docker ps --filter "name=olympus-postgres" --format "{{.Names}}" 2>$null

    if ($running -eq "olympus-postgres") {
        Write-Ok "Container 'olympus-postgres' is already running."
    } else {
        $stopped = docker ps -a --filter "name=olympus-postgres" --format "{{.Names}}" 2>$null

        if ($stopped -eq "olympus-postgres") {
            Write-Warn "Removing stopped 'olympus-postgres' container."
            docker rm olympus-postgres | Out-Null
        }

        docker run `
            --name olympus-postgres `
            -e POSTGRES_USER=$DbUser `
            -e POSTGRES_PASSWORD=$DbPassword `
            -e POSTGRES_DB=$DbName `
            -p "${DbPort}:5432" `
            -d postgres:16 | Out-Null

        Write-Ok "Container started. Waiting for Postgres..."

        $ready = $false

        for ($i = 0; $i -lt 30; $i++) {
            Start-Sleep -Seconds 1
            docker exec olympus-postgres pg_isready -U $DbUser -d $DbName 2>$null | Out-Null

            if ($LASTEXITCODE -eq 0) {
                $ready = $true
                break
            }
        }

        if (-not $ready) {
            Write-Fail "Postgres did not become ready. Run: docker logs olympus-postgres"
        }

        Write-Ok "PostgreSQL Docker container is ready."
    }
} else {
    Write-Fail "PostgreSQL is not reachable at ${DbHost}:${DbPort}. Start it, or run with -StartDocker."
}

# ---------------------------------------------------------------------------
# 5. Python virtual environment
# ---------------------------------------------------------------------------

Write-Step "Setting up Python virtual environment"

$venvDir = Join-Path $RepoRoot ".venv"
$activateScript = Join-Path $venvDir "Scripts\Activate.ps1"

if (-not (Test-Path $venvDir)) {
    python -m venv $venvDir
    Write-Ok "Virtual environment created at .venv"
} else {
    Write-Ok "Virtual environment already exists."
}

if (-not (Test-Path $activateScript)) {
    Write-Fail "Cannot find .venv\Scripts\Activate.ps1. Delete .venv and rerun."
}

. $activateScript
Write-Ok "Virtual environment activated."

# ---------------------------------------------------------------------------
# 6. Install Python dependencies
# ---------------------------------------------------------------------------

if (-not $SkipInstall) {
    Write-Step "Installing Python dependencies"

    Clear-PipTempJunk -RepoRoot $RepoRoot

    python -m pip install --upgrade pip --quiet
    if ($LASTEXITCODE -ne 0) {
        Write-Warn "pip upgrade returned exit code $LASTEXITCODE. Continuing."
    }

    $requirements = Join-Path $RepoRoot "requirements.txt"
    $requirementsDev = Join-Path $RepoRoot "requirements-dev.txt"

    if (Test-Path $requirements) {
        python -m pip install --quiet -r $requirements
        if ($LASTEXITCODE -ne 0) {
            Write-Fail "Failed to install requirements.txt"
        }
    } else {
        Write-Warn "requirements.txt not found."
    }

    if (Test-Path $requirementsDev) {
        python -m pip install --quiet -r $requirementsDev
        if ($LASTEXITCODE -ne 0) {
            Write-Fail "Failed to install requirements-dev.txt"
        }
    }

    Write-Ok "Installing Olympus package in editable mode."

    Push-Location $RepoRoot
    python -m pip install --quiet -e ".[dev]"
    $editableExit = $LASTEXITCODE
    Pop-Location

    if ($editableExit -ne 0) {
        Write-Warn "Editable install with [dev] returned exit code $editableExit. Trying plain editable install."
        Clear-PipTempJunk -RepoRoot $RepoRoot

        python -m pip install --quiet -e $RepoRoot
        $plainEditableExit = $LASTEXITCODE

        if ($plainEditableExit -ne 0) {
            Write-Warn "Plain editable install returned exit code $plainEditableExit. Continuing because maturin will install the Rust package next."
        }
    }

    Write-Ok "Dependency step complete."
} else {
    Write-Ok "Skipping dependency installation."
}

# ---------------------------------------------------------------------------
# 7. Install public UX dependencies
# ---------------------------------------------------------------------------

if (-not $SkipUi -and -not $SkipInstall) {
    Install-PublicUiDeps -UiDir $publicUiDir
} elseif ($SkipUi) {
    Write-Ok "Skipping public UX setup."
} else {
    Write-Ok "Skipping public UX dependency installation."
}

# ---------------------------------------------------------------------------
# 8. Build Rust/Python extension
# ---------------------------------------------------------------------------

if (-not $SkipRustBuild) {
    Write-Step "Building Rust/Python extension with maturin"

    if (-not (Test-Command "maturin")) {
        Write-Warn "maturin not found on PATH. Installing maturin into the venv."
        python -m pip install maturin --quiet

        if ($LASTEXITCODE -ne 0) {
            Write-Fail "Failed to install maturin."
        }
    }

    Push-Location $RepoRoot
    try {
        if ($ReleaseRustBuild) {
            python -m maturin develop --release
        } else {
            python -m maturin develop
        }

        if ($LASTEXITCODE -ne 0) {
            Write-Fail "maturin develop failed with exit code $LASTEXITCODE"
        }
    } catch {
        Write-Fail "maturin develop failed: $_"
    } finally {
        Pop-Location
    }

    Write-Ok "Rust/Python extension installed into the active venv."
} else {
    Write-Warn "Skipping Rust extension build. SMT tests may be skipped."
}

# ---------------------------------------------------------------------------
# 9. Build/Test native Windows Go sequencer
# ---------------------------------------------------------------------------

$goSequencerDirs = @()

if (-not $SkipGoSequencer) {
    if ($BuildGoSequencer -or $TestGoSequencer -or $StartGoSequencer -or $RunSequencerSmokeTests -or $RequireGoSequencer) {
        Write-Step "Checking native Windows Go sequencer"

        $hasGo = Test-GoToolchain

        if ($hasGo) {
            $goSequencerDirs = @(Find-GoSequencerDirs -Root $RepoRoot)

            if ($goSequencerDirs.Count -eq 0) {
                if ($RequireGoSequencer) {
                    Write-Fail "No Go sequencer go.mod found under repo."
                } else {
                    Write-Warn "No Go sequencer go.mod found. Skipping Go sequencer build/test/start."
                }
            } else {
                foreach ($goDir in $goSequencerDirs) {
                    Write-Ok "Found Go sequencer candidate: $goDir"

                    Push-Location $goDir
                    try {
                        if ($TestGoSequencer) {
                            Write-Step "Running Go sequencer tests in $goDir"
                            go test ./...

                            if ($LASTEXITCODE -ne 0) {
                                Write-Fail "Go sequencer tests failed in $goDir"
                            }

                            Write-Ok "Go sequencer tests passed in $goDir"
                        }

                        if ($BuildGoSequencer) {
                            Write-Step "Building Go sequencer in $goDir"
                            go build ./...

                            if ($LASTEXITCODE -ne 0) {
                                Write-Fail "Go sequencer build failed in $goDir"
                            }

                            Write-Ok "Go sequencer build passed in $goDir"
                        }
                    } finally {
                        Pop-Location
                    }
                }

                if ($StartGoSequencer -and -not $UseWslSequencer) {
                    Start-GoSequencerServer -SequencerDir $goSequencerDirs[0] -Addr $SequencerHttpAddr -DbMode $SequencerDbMode
                }
            }
        }
    } else {
        Write-Ok "Native Go sequencer build/test/start not requested."
    }
} else {
    Write-Warn "Go sequencer skipped."
}

# ---------------------------------------------------------------------------
# 10. Optional WSL CDHS-SMF + Go sequencer
# ---------------------------------------------------------------------------

if ($UseWslSequencer -or $StartWslCdhsSmf -or $StartWslGoSequencer) {
    Write-Step "Preparing WSL live sequencer path"

    Test-WslAvailable

    $resolvedWslRepoPath = Convert-ToWslPath -WindowsPath $RepoRoot
    $resolvedWslDbHost = Get-WslDbHost

    Write-Ok "WSL repo path: $resolvedWslRepoPath"
    Write-Ok "WSL DB host: $resolvedWslDbHost"
    Write-Ok "WSL CDHS socket: $WslCdhsSocket"
    Write-Ok "WSL sequencer HTTP addr: $WslSequencerHttpAddr"

    Write-Warn "WSL must have Rust, Cargo, and Go installed for live CDHS/sequencer."
    Write-Warn "If Postgres rejects WSL connections, change postgresql.conf/listen_addresses or use WSL-hosted Postgres."

    # Fast preflight: fail clearly before starting hidden WSL daemons.
    $wslToolCheck = "command -v cargo >/dev/null 2>&1 && command -v go >/dev/null 2>&1 && command -v openssl >/dev/null 2>&1"
    if ($WslDistro) {
        wsl.exe -d $WslDistro -- bash -lc $wslToolCheck | Out-Null
    } else {
        wsl.exe -- bash -lc $wslToolCheck | Out-Null
    }
    if ($LASTEXITCODE -ne 0) {
        Write-Fail "WSL is missing cargo, go, or openssl. Install them in WSL, or remove -StartWslCdhsSmf/-StartWslGoSequencer from the launcher."
    }

    if ($StartWslCdhsSmf) {
        Start-WslCdhsSmfServer -WslRepo $resolvedWslRepoPath -SocketPath $WslCdhsSocket
    }

    if ($StartWslCdhsSmf -and $StartWslGoSequencer) {
        Wait-WslSocket -SocketPath $WslCdhsSocket -TimeoutSeconds 240
    }

    if ($StartWslGoSequencer) {
        Start-WslGoSequencerServer `
            -WslRepo $resolvedWslRepoPath `
            -SocketPath $WslCdhsSocket `
            -HttpAddr $WslSequencerHttpAddr `
            -DbHostForWsl $resolvedWslDbHost

        Start-Sleep -Seconds 5
    }
}

# ---------------------------------------------------------------------------
# 11. Database state / Alembic
# ---------------------------------------------------------------------------

if ($ResetDb) {
    Write-Step "Resetting dev database schema"

    Write-Warn "Dropping and recreating public schema in database '$DbName'."
    Invoke-PostgresSql -Sql "DROP SCHEMA public CASCADE; CREATE SCHEMA public;"

    Write-Ok "Database schema reset."
}

if ($StampHead) {
    Write-Step "Stamping Alembic head"

    Push-Location $RepoRoot
    try {
        Invoke-AlembicStamp -Revision "head"
    } catch {
        Write-Fail "Alembic stamp failed: $_"
    } finally {
        Pop-Location
    }

    Write-Ok "Alembic stamped to head."
}

if (-not $SkipMigrations) {
    Write-Step "Running Alembic migrations"

    try {
        Invoke-AlembicUpgradeHeadWithRecovery -RepoRoot $RepoRoot
    } catch {
        Write-Fail "Alembic migration failed: $_`nIf tables already exist but alembic_version is missing, try: .\setup-windows.ps1 -SkipStart -ForceLocalDbUrl -StampHead"
    }

    Write-Ok "Database schema is up to date."
} else {
    Write-Ok "Skipping Alembic migrations."
}

# ---------------------------------------------------------------------------
# 12. Optional smoke tests
# ---------------------------------------------------------------------------

if ($RunSequencerSmokeTests) {
    Run-SequencerSmokeTests -RepoRoot $RepoRoot
}

# ---------------------------------------------------------------------------
# 13. Success summary
# ---------------------------------------------------------------------------

Write-Host ""
Write-Host "==================================================" -ForegroundColor Green
Write-Host "   Olympus setup ready                            " -ForegroundColor Green
Write-Host "==================================================" -ForegroundColor Green
Write-Host "   API:           http://localhost:8000" -ForegroundColor Green
Write-Host "   API docs:      http://localhost:8000/docs" -ForegroundColor Green
if (-not $SkipUi) {
    Write-Host "   UX:            http://localhost:$UiPort" -ForegroundColor Green
}
Write-Host "   Database:      $(Mask-DatabaseUrl $env:DATABASE_URL)" -ForegroundColor Green
Write-Host "   Psycopg:       $(Mask-DatabaseUrl $env:PSYCOPG_URL)" -ForegroundColor Green
Write-Host "   Max upload:    $env:MAX_UPLOAD_BYTES" -ForegroundColor Green
Write-Host "   Go seq flag:   OLYMPUS_USE_GO_SEQUENCER=$env:OLYMPUS_USE_GO_SEQUENCER" -ForegroundColor Green
Write-Host "   Go seq URL:    $env:GO_SEQUENCER_URL" -ForegroundColor Green
Write-Host "   Insecure DB:   SEQUENCER_ALLOW_INSECURE_DB=$env:SEQUENCER_ALLOW_INSECURE_DB" -ForegroundColor Green

if ($env:SEQUENCER_DB_URL) {
    Write-Host "   Go seq DB:     $(Mask-DatabaseUrl $env:SEQUENCER_DB_URL)" -ForegroundColor Green
} elseif ($env:SEQUENCER_DB_HOST) {
    Write-Host "   Go seq DB:     ${env:SEQUENCER_DB_USER}:***@${env:SEQUENCER_DB_HOST}:${env:SEQUENCER_DB_PORT}/${env:SEQUENCER_DB_NAME}" -ForegroundColor Green
}

if ($UseWslSequencer -or $StartWslCdhsSmf -or $StartWslGoSequencer) {
    Write-Host "   WSL mode:      enabled" -ForegroundColor Green
    Write-Host "   WSL socket:    $WslCdhsSocket" -ForegroundColor Green
    Write-Host "   WSL HTTP:      $WslSequencerHttpAddr" -ForegroundColor Green
}

Write-Host "==================================================" -ForegroundColor Green

Write-Host ""
Write-Host "Useful test commands:" -ForegroundColor Cyan
Write-Host "  python -m pytest tests\test_storage_protocol.py tests\test_smt_incremental.py -vv --tb=short" -ForegroundColor White
Write-Host "  python -m pytest tests\test_sequencer_client_errors.py tests\test_sequencer_integration.py tests\test_sequencer_batch_validation.py tests\test_sequencer_content_contract.py tests\test_sequencer_env_aliases.py tests\test_sequencer_metadata_propagation.py tests\test_sequencer_migration.py -vv --tb=short" -ForegroundColor White
Write-Host "  python -m pytest tests\test_sequencer_client_smoke.py -vv --tb=short    # requires live WSL sequencer/CDHS" -ForegroundColor White
Write-Host "  python -m pytest tests\test_witness_router.py -vv --tb=short" -ForegroundColor White

Write-Host ""
Write-Host "Recommended WSL live path:" -ForegroundColor Cyan
Write-Host "  .\setup-windows.ps1 -SkipStart -ForceLocalDbUrl -SkipMigrations -EnableGoSequencer -UseWslSequencer -WslDbHost 127.0.0.1 -StartWslCdhsSmf -StartWslGoSequencer" -ForegroundColor White

if ($SkipStart) {
    Write-Host ""
    Write-Host "To start the app later:" -ForegroundColor Cyan
    Write-Host "  .\.venv\Scripts\Activate.ps1" -ForegroundColor White
    Write-Host "  uvicorn api.app:app --reload --host 0.0.0.0 --port 8000" -ForegroundColor White
    if (-not $SkipUi) {
        Write-Host "  cd app\public-ui" -ForegroundColor White
        Write-Host "  npm run dev -- --host 127.0.0.1 --port $UiPort" -ForegroundColor White
    }
    exit 0
}

# ---------------------------------------------------------------------------
# 14. Start app servers
# ---------------------------------------------------------------------------

Write-Host ""
if (-not $SkipUi) {
    $uiServedUrl = Start-PublicUiServer -UiDir $publicUiDir -Port $UiPort

    # Start-PublicUiServer returns the URL when the pre-built dist is served by
    # FastAPI; $null means Vite dev-server is starting on $UiPort.
    $targetUrl = $BrowserUrl
    if (-not $targetUrl) {
        if ($uiServedUrl) {
            $targetUrl = $uiServedUrl   # bundled dist → open API port (8000)
        } else {
            $targetUrl = "http://localhost:$UiPort"  # Vite dev server
        }
    }

    Open-BrowserUrl -Url $targetUrl

    if ($CloseLauncherSplash) {
        Close-LauncherSplash
    }
}

Write-Host "Starting API server -- press Ctrl+C to stop." -ForegroundColor Cyan
Write-Host ""

uvicorn api.app:app --reload --host 0.0.0.0 --port 8000
