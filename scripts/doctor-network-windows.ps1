<#
.SYNOPSIS
    Check for accidental public listeners on Olympus/dev ports.

.DESCRIPTION
    Diagnostic-only local lockdown check. It fails when one of the watched
    Olympus or development ports is listening on a wildcard address
    (`0.0.0.0` or `::`). It does not stop processes or change firewall rules.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File scripts\doctor-network-windows.ps1

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File scripts\doctor-network-windows.ps1 -Ports 5173,8001,5433
#>

param(
    [int[]]$Ports = @(5173, 8000, 8001, 5432, 5433, 3737),
    [switch]$AllWildcards
)

$ErrorActionPreference = "Stop"

function Format-ProcessName {
    param([uint32]$ProcessId)

    if ($ProcessId -eq 0) {
        return "System"
    }

    try {
        return (Get-Process -Id $ProcessId -ErrorAction Stop).ProcessName
    } catch {
        return "pid:$ProcessId"
    }
}

function Test-NoTcpConnectionMatch {
    param($ErrorRecord)

    return ($ErrorRecord.FullyQualifiedErrorId -like "CmdletizationQuery_NotFound,*") -or
        ($ErrorRecord.Exception.Message -like "*No matching MSFT_NetTCPConnection objects found*")
}

function Get-ListeningTcpConnections {
    try {
        return @(Get-NetTCPConnection -State Listen -ErrorAction Stop)
    } catch {
        if (Test-NoTcpConnectionMatch -ErrorRecord $_) {
            return @()
        }
        throw
    }
}

$wildcardAddresses = @("0.0.0.0", "::")

$listeners = Get-ListeningTcpConnections |
    Where-Object {
        if ($AllWildcards) {
            $_.LocalAddress -in $wildcardAddresses
        } else {
            ($_.LocalPort -in $Ports) -and ($_.LocalAddress -in $wildcardAddresses)
        }
    } |
    Sort-Object LocalPort, LocalAddress

if (-not $listeners) {
    if ($AllWildcards) {
        Write-Host "OK: no wildcard TCP listeners found." -ForegroundColor Green
    } else {
        Write-Host "OK: watched ports are not listening on 0.0.0.0 or ::." -ForegroundColor Green
        Write-Host "Watched ports: $($Ports -join ', ')"
    }
    exit 0
}

Write-Host "FAIL: wildcard TCP listeners detected." -ForegroundColor Red
Write-Host ""

$listeners | ForEach-Object {
    $proc = Format-ProcessName -ProcessId $_.OwningProcess
    [pscustomobject]@{
        LocalAddress = $_.LocalAddress
        LocalPort    = $_.LocalPort
        Process      = $proc
        Pid          = $_.OwningProcess
    }
} | Format-Table -AutoSize

Write-Host ""
if ($AllWildcards) {
    Write-Host "Review every listener above. Some OS services may be intentional."
} else {
    Write-Host "Olympus dev services should bind loopback only: 127.0.0.1, ::1, or localhost."
    Write-Host "Reconfigure the listed process before exposing this machine to an untrusted network."
}

exit 1
