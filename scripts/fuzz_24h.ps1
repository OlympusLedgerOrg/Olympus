# =============================================================================
# scripts/fuzz_24h.ps1 — 24-hour local reliability and security fuzz marathon
#                         (Windows PowerShell equivalent of fuzz_24h.sh)
#
# Usage:
#   pwsh scripts/fuzz_24h.ps1 [-SecurityOnly] [-StorageOnly] [-Smoke]
#
# Parameters:
#   -SecurityOnly   Run only security invariant fuzzing
#   -StorageOnly    Run only storage/ledger invariant fuzzing
#   -Smoke          Run a short smoke pass (< 3 min, equivalent to CI)
#
# Environment variables (set before calling, or as $env: assignments):
#   TEST_DATABASE_URL   PostgreSQL URL for storage layer tests
#   FUZZ_HOURS          Override run duration in hours (default: 24)
#   FUZZ_MAX_EXAMPLES   Override max Hypothesis examples per test (default: 10000)
#
# All fuzzing is strictly local — no third-party targets, no network scanning.
# =============================================================================
[CmdletBinding()]
param(
    [switch]$SecurityOnly,
    [switch]$StorageOnly,
    [switch]$Smoke
)

$ErrorActionPreference = 'Stop'

$RepoRoot = (Resolve-Path "$PSScriptRoot/..").Path
Set-Location $RepoRoot

# ---------------------------------------------------------------------------
# Profile selection
# ---------------------------------------------------------------------------
if ($Smoke) {
    if (-not $env:HYPOTHESIS_PROFILE) { $env:HYPOTHESIS_PROFILE = "fuzz_smoke" }
    if (-not $env:FUZZ_MAX_EXAMPLES)  { $env:FUZZ_MAX_EXAMPLES  = "30" }
    $FuzzHours = 0
} else {
    if (-not $env:HYPOTHESIS_PROFILE) { $env:HYPOTHESIS_PROFILE = "fuzz_24h" }
    if (-not $env:FUZZ_MAX_EXAMPLES)  { $env:FUZZ_MAX_EXAMPLES  = "10000" }
    $FuzzHours = if ($env:FUZZ_HOURS) { [int]$env:FUZZ_HOURS } else { 24 }
}

Write-Host "=== Olympus Fuzz Marathon ==="
Write-Host "  Profile:          $($env:HYPOTHESIS_PROFILE)"
Write-Host "  Max examples:     $($env:FUZZ_MAX_EXAMPLES)"
if ($FuzzHours -gt 0) { Write-Host "  Duration:         ${FuzzHours}h" }
Write-Host "  TEST_DATABASE_URL: $(if ($env:TEST_DATABASE_URL) { $env:TEST_DATABASE_URL } else { '(not set, storage tests skipped)' })"
Write-Host ""

# ---------------------------------------------------------------------------
# Marker selector
# ---------------------------------------------------------------------------
$Marker = if ($Smoke)          { "fuzz" }
          elseif ($SecurityOnly) { "fuzz and security" }
          elseif ($StorageOnly)  { "fuzz and storage" }
          else                   { "fuzz" }

# ---------------------------------------------------------------------------
# Artifact directory
# ---------------------------------------------------------------------------
$ArtifactDir = Join-Path $RepoRoot ".hypothesis\fuzz-artifacts"
New-Item -ItemType Directory -Force -Path $ArtifactDir | Out-Null

# ---------------------------------------------------------------------------
# Module selection
# ---------------------------------------------------------------------------
function Get-FuzzModules {
    $modules = @()
    if (-not $StorageOnly) {
        $modules += "tests/fuzz/test_security_invariants_fuzz.py"
    }
    if (-not $SecurityOnly -and $env:TEST_DATABASE_URL) {
        $modules += "tests/fuzz/test_storage_invariants_fuzz.py"
    }
    return $modules
}

$Modules = Get-FuzzModules
if ($Modules.Count -eq 0) {
    Write-Warning "No fuzz modules to run (set TEST_DATABASE_URL for storage tests)."
    exit 0
}

# ---------------------------------------------------------------------------
# Smoke mode
# ---------------------------------------------------------------------------
if ($Smoke) {
    Write-Host "--- Smoke pass ---"
    & pytest @Modules -v --tb=short -m $Marker --hypothesis-seed=0
    Write-Host "Smoke pass complete."
    exit $LASTEXITCODE
}

# ---------------------------------------------------------------------------
# Marathon mode
# ---------------------------------------------------------------------------
$StartTime = Get-Date
$EndTime   = $StartTime.AddHours($FuzzHours)
$Pass      = 0

Write-Host "Marathon start: $StartTime"
Write-Host "Marathon end:   $EndTime"
Write-Host ""

while ((Get-Date) -lt $EndTime) {
    $Pass++
    $Seed = (Get-Random -Minimum 1 -Maximum 2147483647)
    Write-Host "=== Pass $Pass ($(Get-Date -Format 'o')) seed=$Seed ==="

    & pytest @Modules -v --tb=short -m $Marker --hypothesis-seed=$Seed
    if ($LASTEXITCODE -ne 0) {
        Write-Warning "FAILURE detected on pass $Pass (seed=$Seed). Artifacts:"
        Get-ChildItem "$ArtifactDir\*.json" -ErrorAction SilentlyContinue |
            Sort-Object LastWriteTime -Descending |
            Select-Object -First 5 |
            Format-Table Name, Length, LastWriteTime
        # Continue running to accumulate more failures
    }
}

Write-Host ""
Write-Host "=== Marathon complete after $Pass passes ==="
Write-Host "Artifacts saved to: $ArtifactDir"
$artifacts = Get-ChildItem "$ArtifactDir\*.json" -ErrorAction SilentlyContinue
if ($artifacts) { $artifacts | Format-Table Name, Length } else { Write-Host "(no failure artifacts)" }
