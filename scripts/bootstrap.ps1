# scripts/bootstrap.ps1 -- Windows first-boot helper for self-hosted Olympus.
#
# Equivalent to scripts/bootstrap.sh for PowerShell on Windows.
# Run from the repo root or any directory -- the script locates itself.
#
# What it does:
#   * Generates .\secrets\db_password (random, ACL-restricted) if absent.
#   * Copies .env.example -> .env if .env does not exist.
#   * Fills in blank/placeholder values for:
#       POSTGRES_PASSWORD, DATABASE_URL, PSYCOPG_URL
#       OLYMPUS_NODE_REHASH_GATE_SECRET
#       OLYMPUS_SEQUENCER_TOKEN
#       OLYMPUS_INGEST_SIGNING_KEY
#       OLYMPUS_DOMAIN  (defaults to localhost)
#       ACME_EMAIL      (defaults to admin@localhost)
#
# Idempotent: safe to re-run. Never overwrites values you have already set.
#
# Usage:
#   powershell -ExecutionPolicy Bypass -File scripts\bootstrap.ps1

#Requires -Version 5.1
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$RepoRoot   = Split-Path -Parent $PSScriptRoot
$SecretsDir = Join-Path $RepoRoot 'secrets'
$DbPassFile = Join-Path $SecretsDir 'db_password'
$EnvFile    = Join-Path $RepoRoot '.env'
$EnvExample = Join-Path $RepoRoot '.env.example'

$Utf8NoBom = New-Object System.Text.UTF8Encoding($false)

function Log([string]$msg) { Write-Host "[bootstrap] $msg" }

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

function New-RandomHex([int]$bytes) {
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    $buf = New-Object byte[] $bytes
    $rng.GetBytes($buf)
    return ($buf | ForEach-Object { $_.ToString('x2') }) -join ''
}

function New-RandomPassword([int]$length = 40) {
    $chars  = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'
    $rng    = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    $result = New-Object char[] $length
    $oneByte = New-Object byte[] 1
    for ($i = 0; $i -lt $length; $i++) {
        do { $rng.GetBytes($oneByte) } while ($oneByte[0] -ge (256 - (256 % $chars.Length)))
        $result[$i] = $chars[$oneByte[0] % $chars.Length]
    }
    return -join $result
}

# Restrict file to current user only (mirrors chmod 600).
# Uses icacls to avoid requiring SeSecurityPrivilege.
function Set-PrivateFile([string]$path) {
    # /inheritance:r  -- remove inherited ACEs
    # /grant:r        -- replace any existing grant for this user
    # (F)             -- FullControl
    $null = & icacls $path /inheritance:r /grant:r "${env:USERDOMAIN}\${env:USERNAME}:(F)" 2>&1
    if ($LASTEXITCODE -ne 0) {
        # Non-fatal: file is already in the user's own directory; permissions
        # are still reasonable. Just warn and continue.
        Log "WARNING: could not restrict permissions on $path (icacls exit $LASTEXITCODE)."
    }
}

# Read the current value of KEY from the .env file.
function Get-EnvValue([string]$key) {
    $line = Select-String -Path $EnvFile -Pattern "^${key}=" | Select-Object -First 1
    if (-not $line) { return '' }
    return ($line.Line -replace "^${key}=", '')
}

# Write KEY=VALUE into the .env file unconditionally (upsert).
function Write-EnvValue([string]$key, [string]$value) {
    $content = [System.IO.File]::ReadAllText($EnvFile, $Utf8NoBom)
    $escaped = [regex]::Escape($key)
    $pattern = "(?m)^${escaped}=.*$"

    if ($content -match $pattern) {
        $content = [regex]::Replace($content, $pattern, "${key}=${value}")
    } else {
        # Append, ensuring a trailing newline.
        if (-not $content.EndsWith("`n")) { $content += "`n" }
        $content += "${key}=${value}`n"
    }

    [System.IO.File]::WriteAllText($EnvFile, $content, $Utf8NoBom)
    Set-PrivateFile $EnvFile
}

# Set KEY=VALUE in .env only if the current value is blank or still contains
# one of the known placeholder strings. Operator-set values are left alone.
function Set-EnvIfBlank([string]$key, [string]$value, [string[]]$extraPlaceholders = @()) {
    $placeholders = @('change_me_use_a_strong_random_password') + $extraPlaceholders
    $current = Get-EnvValue $key

    if ($current -ne '') {
        $isPlaceholder = $false
        foreach ($p in $placeholders) {
            if ($current -like "*${p}*") { $isPlaceholder = $true; break }
        }
        if (-not $isPlaceholder) { return }
    }

    Write-EnvValue $key $value
}

# ---------------------------------------------------------------------------
# 1. Database password secret
# ---------------------------------------------------------------------------

if (-not (Test-Path $SecretsDir)) {
    New-Item -ItemType Directory -Path $SecretsDir | Out-Null
}

if (Test-Path $DbPassFile) {
    Log "secrets/db_password already exists -- keeping the existing password."
    $DbPassword = [System.IO.File]::ReadAllText($DbPassFile, $Utf8NoBom).TrimEnd("`r`n")
} else {
    Log "Generating a new random database password at secrets\db_password..."
    $DbPassword = New-RandomPassword 40
    [System.IO.File]::WriteAllText($DbPassFile, $DbPassword, $Utf8NoBom)
    Set-PrivateFile $DbPassFile
    Log "Wrote secrets\db_password (restricted to current user)."
}

# ---------------------------------------------------------------------------
# 2. .env file
# ---------------------------------------------------------------------------

if (-not (Test-Path $EnvExample)) {
    Log "ERROR: .env.example is missing -- repository looks broken."
    exit 1
}

if (Test-Path $EnvFile) {
    Log ".env already exists -- preserving it (only filling in blank required values)."
} else {
    Log "Copying .env.example -> .env..."
    Copy-Item $EnvExample $EnvFile
    Set-PrivateFile $EnvFile
}

# Sync Postgres password so uvicorn running directly uses the same credentials
# as the db container.
Set-EnvIfBlank 'POSTGRES_PASSWORD' $DbPassword

$DefaultUser = Get-EnvValue 'DATABASE_USER'
if ($DefaultUser -eq '') { $DefaultUser = 'olympus' }
$DefaultDb = Get-EnvValue 'DATABASE_NAME'
if ($DefaultDb -eq '') { $DefaultDb = 'olympus' }

Set-EnvIfBlank 'DATABASE_URL'  "postgresql+asyncpg://${DefaultUser}:${DbPassword}@db:5432/${DefaultDb}"
Set-EnvIfBlank 'PSYCOPG_URL'   "postgresql://${DefaultUser}:${DbPassword}@db:5432/${DefaultDb}"

# Random tokens required at boot.
$gateSecret = Get-EnvValue 'OLYMPUS_NODE_REHASH_GATE_SECRET'
if ($gateSecret -eq '') {
    Set-EnvIfBlank 'OLYMPUS_NODE_REHASH_GATE_SECRET' (New-RandomHex 32)
    Log "Generated OLYMPUS_NODE_REHASH_GATE_SECRET."
}

$seqToken = Get-EnvValue 'OLYMPUS_SEQUENCER_TOKEN'
if ($seqToken -eq '') {
    Set-EnvIfBlank 'OLYMPUS_SEQUENCER_TOKEN' (New-RandomHex 32)
    Log "Generated OLYMPUS_SEQUENCER_TOKEN."
}

$signingKey = Get-EnvValue 'OLYMPUS_INGEST_SIGNING_KEY'
if ($signingKey -eq '') {
    Set-EnvIfBlank 'OLYMPUS_INGEST_SIGNING_KEY' (New-RandomHex 32)
    Log "Generated OLYMPUS_INGEST_SIGNING_KEY (Ed25519 seed)."
}

# Safe local-dev defaults for Traefik / Let's Encrypt.
$domain = Get-EnvValue 'OLYMPUS_DOMAIN'
if (($domain -eq '') -or ($domain -like '*yourdomain*')) {
    Set-EnvIfBlank 'OLYMPUS_DOMAIN' 'localhost' @('yourdomain')
    Log "Set OLYMPUS_DOMAIN=localhost (update for production)."
}

$email = Get-EnvValue 'ACME_EMAIL'
if (($email -eq '') -or ($email -like '*yourdomain*')) {
    Set-EnvIfBlank 'ACME_EMAIL' 'admin@localhost' @('yourdomain')
    Log "Set ACME_EMAIL=admin@localhost (update for production)."
}

Log "Bootstrap complete."
Log ""
Log "Next steps:"
Log "  1. Edit .env to set your real OLYMPUS_DOMAIN, ACME_EMAIL, and"
Log "     ANTHROPIC_API_KEY before a production deployment."
Log "  2. Bring the stack up:"
Log "       docker compose up -d"
Log "     Or, with the Go sequencer profile:"
Log "       docker compose --profile sequencer up -d"
