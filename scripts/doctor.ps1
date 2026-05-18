#Requires -Version 5.1
Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$Root = Resolve-Path (Join-Path $PSScriptRoot "..")
Set-Location $Root

$script:Failures = 0
$script:Warnings = 0

function Write-Check {
    param([string]$Level, [string]$Message)
    Write-Host "[$Level] $Message"
}

function Pass([string]$Message) { Write-Check "OK" $Message }
function Info([string]$Message) { Write-Check "INFO" $Message }
function Warn([string]$Message) { $script:Warnings += 1; Write-Check "WARN" $Message }
function Fail([string]$Message) { $script:Failures += 1; Write-Check "ERROR" $Message }

function Get-CommandPath([string]$Name) {
    $cmd = Get-Command $Name -ErrorAction SilentlyContinue
    if ($cmd) { return $cmd.Source }
    return $null
}

function Read-EnvFile([string]$Path) {
    $values = @{}
    if (-not (Test-Path -LiteralPath $Path)) { return $values }
    foreach ($line in Get-Content -LiteralPath $Path) {
        $trimmed = $line.Trim()
        if (-not $trimmed -or $trimmed.StartsWith("#")) { continue }
        $parts = $trimmed.Split("=", 2)
        if ($parts.Count -ne 2) { continue }
        $key = $parts[0].Trim()
        $value = $parts[1].Trim().Trim('"').Trim("'")
        $values[$key] = $value
    }
    return $values
}

function Get-HostFromValue([string]$Value) {
    if (-not $Value) { return "" }
    if ($Value -match "^[a-zA-Z][a-zA-Z0-9+.-]*://") {
        try { return ([Uri]$Value).Host.ToLowerInvariant() } catch { }
        if ($Value -match "^[a-zA-Z][a-zA-Z0-9+.-]*://(?:[^@/]+@)?([^/:?#]+)") {
            return $Matches[1].ToLowerInvariant()
        }
    }
    return ""
}

function Test-CommandVersion([string]$Name, [string[]]$VersionArgs) {
    $path = Get-CommandPath $Name
    if (-not $path) {
        Fail "$Name not found on PATH"
        return
    }
    $previousErrorAction = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    try {
        $output = & $Name @VersionArgs 2>&1
        $exitCode = $LASTEXITCODE
    } finally {
        $ErrorActionPreference = $previousErrorAction
    }
    $version = $output | Select-Object -First 1
    if ($exitCode -eq 0) {
        Pass "$Name found: $version"
    } else {
        Fail "$Name found but version check failed: $version"
    }
}

Info "Checking native Windows development prerequisites"
Test-CommandVersion "python" @("--version")
Test-CommandVersion "node" @("--version")
Test-CommandVersion "npm" @("--version")
Test-CommandVersion "git" @("--version")
Test-CommandVersion "psql" @("--version")
if (-not (Get-CommandPath "psql")) {
    $candidateBins = @(
        "C:\Program Files\PostgreSQL\18\bin",
        "C:\Program Files\PostgreSQL\17\bin",
        "C:\Program Files\PostgreSQL\16\bin"
    )
    $foundBin = $candidateBins | Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1
    if ($foundBin) {
        Warn "Add $foundBin to PATH and reopen PowerShell"
    } else {
        Warn "Install PostgreSQL 18, or add your PostgreSQL 16+ bin directory to PATH and reopen PowerShell"
    }
}

try {
    $client = New-Object System.Net.Sockets.TcpClient
    $async = $client.BeginConnect("127.0.0.1", 5432, $null, $null)
    if ($async.AsyncWaitHandle.WaitOne(1500) -and $client.Connected) {
        $client.EndConnect($async)
        Pass "PostgreSQL is accepting TCP connections on 127.0.0.1:5432"
    } else {
        Fail "PostgreSQL is not accepting TCP connections on 127.0.0.1:5432"
    }
    $client.Close()
} catch {
    Fail "PostgreSQL check failed on 127.0.0.1:5432: $($_.Exception.Message)"
}

if (Test-Path -LiteralPath ".venv\Scripts\python.exe") {
    Pass ".venv exists"
} else {
    Fail ".venv is missing; run .\scripts\setup-windows.ps1"
}

if (Test-Path -LiteralPath ".env.local") {
    Pass ".env.local exists"
} else {
    Fail ".env.local is missing; run .\scripts\setup-windows.ps1"
}

if ((Test-Path -LiteralPath "alembic.ini") -and (Test-Path -LiteralPath "alembic\versions")) {
    Pass "Alembic files are present"
} else {
    Fail "Alembic files are missing"
}

if (Test-Path -LiteralPath ".venv\Scripts\python.exe") {
    try {
        & ".venv\Scripts\python.exe" -m alembic --version *> $null
        if ($LASTEXITCODE -eq 0) { Pass "Alembic is installed in .venv" } else { Fail "Alembic is not ready in .venv" }
    } catch {
        Fail "Alembic check failed: $($_.Exception.Message)"
    }
} else {
    Warn "Skipped Alembic package check because .venv is missing"
}

$envValues = Read-EnvFile ".env.local"
if ($envValues.Count -gt 0) {
    $dockerHosts = @("db", "postgres", "app")
    foreach ($name in @("DATABASE_URL", "PSYCOPG_URL", "TEST_DATABASE_URL", "API_BASE_URL", "VITE_API_BASE", "OLYMPUS_SEQUENCER_URL")) {
        if (-not $envValues.ContainsKey($name)) { continue }
        $hostName = Get-HostFromValue $envValues[$name]
        if ($dockerHosts -contains $hostName) {
            Fail "$name uses Docker hostname '$hostName'; native .env.local must use 127.0.0.1 or localhost"
        }
    }
    foreach ($name in @("DATABASE_HOST")) {
        if ($envValues.ContainsKey($name) -and ($dockerHosts -contains $envValues[$name].ToLowerInvariant())) {
            Fail "$name uses Docker hostname '$($envValues[$name])'; native .env.local must use 127.0.0.1 or localhost"
        }
    }
}

if ($script:Failures -gt 0) {
    Write-Check "ERROR" "Doctor found $script:Failures error(s) and $script:Warnings warning(s)"
    exit 1
}

Write-Check "OK" "Doctor passed with $script:Warnings warning(s)"
