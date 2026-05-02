#Requires -Version 5.1
<#
.SYNOPSIS
    Olympus admin CLI — user onboarding, key management, service control.

.EXAMPLE
    .\scripts\olympus.ps1 register -Email bob@example.com -Password "correct-horse-battery"
    .\scripts\olympus.ps1 login    -Email bob@example.com -Password "correct-horse-battery"
    .\scripts\olympus.ps1 keys     -ApiKey <raw-key>
    .\scripts\olympus.ps1 revoke   -ApiKey <raw-key> -KeyId <id>
    .\scripts\olympus.ps1 reload   -AdminKey <admin-key>
    .\scripts\olympus.ps1 up
    .\scripts\olympus.ps1 down
    .\scripts\olympus.ps1 rebuild
    .\scripts\olympus.ps1 logs
    .\scripts\olympus.ps1 status
#>
param(
    [Parameter(Position=0, Mandatory)]
    [ValidateSet("register","login","keys","revoke","reload","up","down","rebuild","logs","status")]
    [string]$Command,

    [string]$Email,
    [string]$Password,
    [string]$ApiKey,
    [string]$AdminKey,
    [string]$KeyId,
    [string]$KeyName   = "",
    [string[]]$Scopes  = @("ingest","verify"),
    [string]$Expires   = "2099-01-01T00:00:00Z",
    [string]$BaseUrl   = "http://localhost:8090"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# ── helpers ───────────────────────────────────────────────────────────────────

function Write-Header([string]$text) {
    Write-Host ""
    Write-Host ("=" * 60) -ForegroundColor DarkGreen
    Write-Host "  $text" -ForegroundColor Green
    Write-Host ("=" * 60) -ForegroundColor DarkGreen
}

function Write-Field([string]$label, [string]$value, [switch]$Sensitive) {
    $display = if ($Sensitive) { $value } else { $value }
    Write-Host ("  {0,-18} " -f $label) -NoNewline -ForegroundColor DarkGreen
    Write-Host $display -ForegroundColor White
}

function Copy-ToClipboard([string]$value) {
    try { Set-Clipboard -Value $value; Write-Host "  (copied to clipboard)" -ForegroundColor DarkGray }
    catch { }
}

function Invoke-Api {
    param(
        [string]$Method = "GET",
        [string]$Path,
        [hashtable]$Headers = @{},
        [object]$Body
    )
    $uri = "$BaseUrl$Path"
    $params = @{
        UseBasicParsing = $true
        Method          = $Method
        Uri             = $uri
        Headers         = $Headers
    }
    if ($Body) {
        $params.Body        = ($Body | ConvertTo-Json -Compress)
        $params.ContentType = "application/json"
    }
    try {
        $resp = Invoke-WebRequest @params
        return $resp.Content | ConvertFrom-Json
    } catch {
        $status = $_.Exception.Response.StatusCode.value__
        try {
            $detail = $_.ErrorDetails.Message | ConvertFrom-Json
            $msg = if ($detail.detail -is [string]) { $detail.detail } else { $detail.detail.detail }
        } catch {
            $msg = $_.Exception.Message
        }
        Write-Host ""
        Write-Host "  ERROR $status`: $msg" -ForegroundColor Red
        Write-Host ""
        exit 1
    }
}

function Require([string]$value, [string]$flag) {
    if (-not $value) {
        Write-Host "  -$flag is required for this command." -ForegroundColor Red
        exit 1
    }
}

# ── commands ──────────────────────────────────────────────────────────────────

switch ($Command) {

    "register" {
        Require $Email    "Email"
        Require $Password "Password"

        Write-Header "REGISTERING USER"
        $name = if ($KeyName) { $KeyName } else { ($Email -split "@")[0] }
        $result = Invoke-Api -Method POST -Path "/auth/register" -Body @{
            email      = $Email
            password   = $Password
            name       = $name
            scopes     = $Scopes
            expires_at = $Expires
        }

        Write-Field "EMAIL"    $result.email
        Write-Field "USER ID"  $result.user_id
        Write-Field "KEY ID"   $result.key_id
        Write-Field "SCOPES"   ($result.scopes -join ", ")
        Write-Host ""
        Write-Host "  API KEY (copy now — not stored, won't be shown again):" -ForegroundColor Yellow
        Write-Host ""
        Write-Host "  $($result.api_key)" -ForegroundColor Cyan
        Copy-ToClipboard $result.api_key
        Write-Host ""
    }

    "login" {
        Require $Email    "Email"
        Require $Password "Password"

        Write-Header "USER KEYS"
        $result = Invoke-Api -Method POST -Path "/auth/login" -Body @{
            email    = $Email
            password = $Password
        }

        Write-Field "EMAIL"   $result.email
        Write-Field "USER ID" $result.user_id
        Write-Host ""

        if ($result.keys.Count -eq 0) {
            Write-Host "  No active keys." -ForegroundColor DarkGray
        } else {
            foreach ($k in $result.keys) {
                Write-Host "  [$($k.id)]" -ForegroundColor DarkGreen
                Write-Host "    name    : $($k.name)"
                Write-Host "    scopes  : $($k.scopes -join ', ')"
                Write-Host "    expires : $($k.expires_at.Substring(0,10))"
                Write-Host ""
            }
        }
    }

    "keys" {
        Require $ApiKey "ApiKey"

        Write-Header "MY ACTIVE KEYS"
        $result = Invoke-Api -Path "/auth/keys" -Headers @{ "X-API-Key" = $ApiKey }

        if ($result.Count -eq 0) {
            Write-Host "  No active keys." -ForegroundColor DarkGray
        } else {
            foreach ($k in $result) {
                Write-Host "  [$($k.id)]" -ForegroundColor DarkGreen
                Write-Host "    name    : $($k.name)"
                Write-Host "    scopes  : $($k.scopes -join ', ')"
                Write-Host "    expires : $($k.expires_at.Substring(0,10))"
                Write-Host ""
            }
        }
    }

    "revoke" {
        Require $ApiKey "ApiKey"
        Require $KeyId  "KeyId"

        Write-Header "REVOKING KEY"
        Invoke-Api -Method DELETE -Path "/auth/keys/$KeyId" -Headers @{ "X-API-Key" = $ApiKey } | Out-Null
        Write-Host "  Revoked $KeyId" -ForegroundColor Green
        Write-Host ""
    }

    "reload" {
        Require $AdminKey "AdminKey"

        Write-Header "RELOADING ENV KEYS"
        $result = Invoke-Api -Method POST -Path "/key/admin/reload-keys" -Headers @{ "X-Admin-Key" = $AdminKey }
        Write-Host "  [ok] $($result.key_count) env key(s) active" -ForegroundColor Green
        Write-Host ""
    }

    "up" {
        Write-Header "STARTING SERVICES"
        docker compose up -d
    }

    "down" {
        Write-Header "STOPPING SERVICES"
        docker compose down
    }

    "rebuild" {
        Write-Header "REBUILDING AND RESTARTING"
        docker compose build --no-cache app public-ui
        docker compose up -d --force-recreate app public-ui
    }

    "logs" {
        docker compose logs app --tail=50 --follow
    }

    "status" {
        Write-Header "SERVICE STATUS"
        docker compose ps
        Write-Host ""
        try {
            $stats = Invoke-Api -Path "/v1/public/stats"
            Write-Host "  API LIVE" -ForegroundColor Green
            Write-Host "    proofs  : $($stats.proofs)"
            Write-Host "    uptime  : $($stats.uptime)"
        } catch {
            Write-Host "  API UNREACHABLE" -ForegroundColor Red
        }
        Write-Host ""
    }
}
