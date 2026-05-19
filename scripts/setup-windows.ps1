#Requires -Version 5.1
Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$Root = Resolve-Path (Join-Path $PSScriptRoot "..")
Set-Location $Root

function Log([string]$Level, [string]$Message) {
    Write-Host "[$Level] $Message"
}

function Ensure-Command([string]$Name) {
    if (-not (Get-Command $Name -ErrorAction SilentlyContinue)) {
        Log "ERROR" "$Name is required but was not found on PATH"
        exit 1
    }
}

function Read-EnvFile([string]$Path) {
    $values = @{}
    if (-not (Test-Path -LiteralPath $Path)) { return $values }
    foreach ($line in Get-Content -LiteralPath $Path) {
        $trimmed = $line.Trim()
        if (-not $trimmed -or $trimmed.StartsWith("#")) { continue }
        $parts = $trimmed.Split("=", 2)
        if ($parts.Count -ne 2) { continue }
        $values[$parts[0].Trim()] = $parts[1].Trim().Trim('"').Trim("'")
    }
    return $values
}

function Set-EnvValue([string]$Path, [string]$Key, [string]$Value) {
    $lines = if (Test-Path -LiteralPath $Path) { @(Get-Content -LiteralPath $Path) } else { @() }
    $updated = $false
    $next = foreach ($line in $lines) {
        if ($line -match "^\s*$([regex]::Escape($Key))\s*=") {
            "$Key=$Value"
            $updated = $true
        } else {
            $line
        }
    }
    if (-not $updated) {
        $next += "$Key=$Value"
    }
    Set-Content -LiteralPath $Path -Value $next -Encoding ASCII
}

function New-RandomHexKey {
    $bytes = New-Object byte[] 32
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    try {
        $rng.GetBytes($bytes)
    } finally {
        $rng.Dispose()
    }
    return -join ($bytes | ForEach-Object { $_.ToString("x2") })
}

Log "INFO" "Preparing native Windows development environment"
Ensure-Command "python"
Ensure-Command "node"
Ensure-Command "npm"
Ensure-Command "git"

if (-not (Test-Path -LiteralPath ".venv\Scripts\python.exe")) {
    Log "INFO" "Creating .venv"
    python -m venv .venv
} else {
    Log "OK" ".venv already exists"
}

$Python = ".venv\Scripts\python.exe"
Log "INFO" "Upgrading pip"
& $Python -m pip install -U pip

Log "INFO" "Installing Python dependencies"
& $Python -m pip install -r requirements.txt -r requirements-dev.txt

if (-not (Test-Path -LiteralPath ".env.local")) {
    if (-not (Test-Path -LiteralPath ".env.local.example")) {
        Log "ERROR" ".env.local.example is missing"
        exit 1
    }
    Copy-Item -LiteralPath ".env.local.example" -Destination ".env.local"
    Log "OK" "Created .env.local from .env.local.example"
} else {
    Log "OK" ".env.local already exists"
}

$envValues = Read-EnvFile ".env.local"
if (-not $envValues.ContainsKey("OLYMPUS_DEV_SIGNING_KEY") -or -not $envValues["OLYMPUS_DEV_SIGNING_KEY"]) {
    Set-EnvValue ".env.local" "OLYMPUS_DEV_SIGNING_KEY" "false"
    Log "OK" "OLYMPUS_DEV_SIGNING_KEY set to false"
} elseif ($envValues["OLYMPUS_DEV_SIGNING_KEY"].ToLowerInvariant() -in @("1", "true", "yes", "on")) {
    Set-EnvValue ".env.local" "OLYMPUS_DEV_SIGNING_KEY" "false"
    Log "WARN" "OLYMPUS_DEV_SIGNING_KEY was true with a persistent database; set it to false"
}

$envValues = Read-EnvFile ".env.local"
if (-not $envValues.ContainsKey("OLYMPUS_INGEST_SIGNING_KEY") -or -not $envValues["OLYMPUS_INGEST_SIGNING_KEY"]) {
    Set-EnvValue ".env.local" "OLYMPUS_INGEST_SIGNING_KEY" (New-RandomHexKey)
    Log "OK" "Generated stable local OLYMPUS_INGEST_SIGNING_KEY"
} elseif ($envValues["OLYMPUS_INGEST_SIGNING_KEY"] -notmatch '^[0-9a-fA-F]{64}$') {
    # Length-only check used to accept any 64-char string, silently admitting
    # invalid keys that would later crash the signer.  Match exact hex shape.
    Log "ERROR" "OLYMPUS_INGEST_SIGNING_KEY must be exactly 64 hex characters (0-9a-f)"
    exit 1
} else {
    Log "OK" "OLYMPUS_INGEST_SIGNING_KEY already exists"
}

if (-not (Test-Path -LiteralPath "app\public-ui\package.json")) {
    Log "ERROR" "app/public-ui/package.json is missing; cannot install UI dependencies"
    exit 1
}

Log "INFO" "Installing UI dependencies from app/public-ui"
Push-Location "app\public-ui"
try {
    if ((Test-Path -LiteralPath "package-lock.json") -and -not (Test-Path -LiteralPath "node_modules")) {
        npm ci
    } else {
        npm install
    }
    if ($LASTEXITCODE -ne 0) {
        Log "ERROR" "npm dependency installation failed"
        exit $LASTEXITCODE
    }
} finally {
    Pop-Location
}

Log "OK" "Native setup complete"
Log "INFO" "Next: .\scripts\doctor.ps1"
Log "INFO" "Then: .\scripts\dev.ps1"
