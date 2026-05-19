#Requires -Version 5.1
Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$Root = Resolve-Path (Join-Path $PSScriptRoot "..")
Set-Location $Root

function Log([string]$Level, [string]$Message) {
    Write-Host "[$Level] $Message"
}

function Load-EnvLocal([string]$Path) {
    if (-not (Test-Path -LiteralPath $Path)) {
        Log "ERROR" ".env.local is missing; run .\scripts\setup-windows.ps1"
        exit 1
    }
    foreach ($line in Get-Content -LiteralPath $Path) {
        $trimmed = $line.Trim()
        if (-not $trimmed -or $trimmed.StartsWith("#")) { continue }
        $parts = $trimmed.Split("=", 2)
        if ($parts.Count -ne 2) { continue }
        $name = $parts[0].Trim()
        $value = $parts[1].Trim().Trim('"').Trim("'")
        [Environment]::SetEnvironmentVariable($name, $value, "Process")
    }
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

function Assert-NativeEnv {
    # `sequencer-go` and `cdhs-smf-rust` are Compose service names just like
    # `db`/`postgres`/`app`; native dev requires 127.0.0.1 or localhost for all
    # of them, otherwise an OLYMPUS_SEQUENCER_URL pointing at `sequencer-go`
    # would slip through and fail at request time.
    $dockerHosts = @("db", "postgres", "app", "sequencer-go", "cdhs-smf-rust")
    foreach ($name in @("DATABASE_URL", "PSYCOPG_URL", "TEST_DATABASE_URL", "API_BASE_URL", "VITE_API_BASE", "OLYMPUS_SEQUENCER_URL")) {
        $value = [Environment]::GetEnvironmentVariable($name, "Process")
        $hostName = Get-HostFromValue $value
        if ($dockerHosts -contains $hostName) {
            Log "ERROR" "$name uses Docker hostname '$hostName'; native dev requires 127.0.0.1 or localhost"
            exit 1
        }
    }
    $databaseHost = [Environment]::GetEnvironmentVariable("DATABASE_HOST", "Process")
    if ($databaseHost -and ($dockerHosts -contains $databaseHost.ToLowerInvariant())) {
        Log "ERROR" "DATABASE_HOST uses Docker hostname '$databaseHost'; native dev requires 127.0.0.1 or localhost"
        exit 1
    }
}

function Stop-ProcessTree {
    param([int]$ProcessId)
    try {
        $children = Get-CimInstance Win32_Process -Filter "ParentProcessId=$ProcessId" -ErrorAction SilentlyContinue
        foreach ($child in $children) {
            Stop-ProcessTree -ProcessId $child.ProcessId
        }
        $proc = Get-Process -Id $ProcessId -ErrorAction SilentlyContinue
        if ($proc) {
            Log "INFO" "Stopping process $ProcessId"
            Stop-Process -Id $ProcessId -Force -ErrorAction SilentlyContinue
        }
    } catch {
        # Surface cleanup failures so orphaned-process bugs are debuggable;
        # silently swallowing them makes "why is port still bound?" guesswork.
        Log "WARN" "Failed to stop process tree rooted at $ProcessId: $($_.Exception.Message)"
    }
}

function Stop-ChildProcesses {
    param([System.Diagnostics.Process[]]$Processes)
    foreach ($proc in $Processes) {
        if ($null -eq $proc) { continue }
        Stop-ProcessTree -ProcessId $proc.Id
    }
}

function Write-LogTail {
    param([string]$Path, [int]$Lines = 40)
    if (Test-Path -LiteralPath $Path) {
        Log "INFO" "Last $Lines lines from $Path"
        Get-Content -LiteralPath $Path -Tail $Lines | ForEach-Object { Write-Host $_ }
    } else {
        Log "WARN" "Log file does not exist: $Path"
    }
}

function Wait-HttpReady {
    param(
        [string]$Name,
        [string]$Url,
        [System.Diagnostics.Process]$Process,
        [string]$ErrorLog,
        [int]$TimeoutSeconds = 45
    )
    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    while ((Get-Date) -lt $deadline) {
        if ($Process.HasExited) {
            Log "ERROR" "$Name process exited with code $($Process.ExitCode)"
            Write-LogTail $ErrorLog
            return $false
        }
        try {
            Invoke-WebRequest -Uri $Url -UseBasicParsing -TimeoutSec 2 -ErrorAction Stop | Out-Null
            return $true
        } catch {
            Start-Sleep -Seconds 1
        }
    }
    Log "ERROR" "$Name did not become ready at $Url within $TimeoutSeconds seconds"
    Write-LogTail $ErrorLog
    return $false
}

if (-not (Test-Path -LiteralPath ".venv\Scripts\python.exe")) {
    Log "ERROR" ".venv is missing; run .\scripts\setup-windows.ps1"
    exit 1
}
if (-not (Test-Path -LiteralPath "app\public-ui\package.json")) {
    Log "ERROR" "app/public-ui/package.json is missing; cannot start UI"
    exit 1
}

Load-EnvLocal ".env.local"
Assert-NativeEnv

$Python = Resolve-Path ".venv\Scripts\python.exe"
$LogDir = Join-Path $Root ".olympus-logs"
New-Item -ItemType Directory -Force -Path $LogDir | Out-Null
$ApiLog = Join-Path $LogDir "native-api.log"
$ApiErrLog = Join-Path $LogDir "native-api.err.log"
$UiLog = Join-Path $LogDir "native-ui.log"
$UiErrLog = Join-Path $LogDir "native-ui.err.log"

Log "INFO" "Running Alembic migrations"
& $Python -m alembic upgrade heads
if ($LASTEXITCODE -ne 0) {
    Log "ERROR" "Alembic migrations failed"
    exit $LASTEXITCODE
}

Log "INFO" "Starting FastAPI on http://127.0.0.1:8000"
$apiArgs = "-NoProfile -ExecutionPolicy Bypass -Command `"& '$Python' -m uvicorn api.main:app --reload --host 127.0.0.1 --port 8000`""
$api = Start-Process -FilePath "powershell.exe" -ArgumentList $apiArgs -WorkingDirectory $Root -PassThru -WindowStyle Hidden -RedirectStandardOutput $ApiLog -RedirectStandardError $ApiErrLog

Log "INFO" "Starting Vite from app/public-ui"
$uiArgs = "-NoProfile -ExecutionPolicy Bypass -Command `"npm run dev -- --host 127.0.0.1`""
$ui = Start-Process -FilePath "powershell.exe" -ArgumentList $uiArgs -WorkingDirectory (Join-Path $Root "app\public-ui") -PassThru -WindowStyle Hidden -RedirectStandardOutput $UiLog -RedirectStandardError $UiErrLog

Log "INFO" "API logs: $ApiLog"
Log "INFO" "API errors: $ApiErrLog"
Log "INFO" "UI logs: $UiLog"
Log "INFO" "UI errors: $UiErrLog"

$children = @($api, $ui)
if (-not (Wait-HttpReady "API" "http://127.0.0.1:8000/health" $api $ApiErrLog 60)) {
    Stop-ChildProcesses $children
    exit 1
}
Log "OK" "API: http://127.0.0.1:8000"

if (-not (Wait-HttpReady "UI" "http://127.0.0.1:5173/" $ui $UiErrLog 60)) {
    Stop-ChildProcesses $children
    exit 1
}
Log "OK" "UI: http://127.0.0.1:5173"
Log "INFO" "Press Ctrl+C here to stop both process trees"

try {
    while ($true) {
        Start-Sleep -Seconds 1
        foreach ($proc in $children) {
            if ($proc.HasExited) {
                Log "ERROR" "Child process $($proc.Id) exited with code $($proc.ExitCode)"
                Stop-ChildProcesses $children
                exit $proc.ExitCode
            }
        }
    }
} finally {
    Stop-ChildProcesses $children
}
