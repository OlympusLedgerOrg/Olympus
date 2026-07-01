param(
    [string]$Dir = ".",
    [string]$Repo = $env:GITHUB_REPOSITORY,
    [ValidateSet("1", "2", "3", "4")]
    [string]$Level = "1",
    [string]$Checksums = "SHA256SUMS"
)

if ([string]::IsNullOrWhiteSpace($Repo)) {
    $Repo = "OlympusLedgerOrg/Olympus"
}

$ErrorActionPreference = "Stop"
Set-Location -LiteralPath $Dir

if (-not (Test-Path -LiteralPath $Checksums -PathType Leaf)) {
    throw "Missing checksum file: $Checksums"
}

$resolved = @()
foreach ($line in Get-Content -LiteralPath $Checksums) {
    if ([string]::IsNullOrWhiteSpace($line) -or $line.TrimStart().StartsWith("#")) {
        continue
    }
    if ($line -notmatch '^(?<hash>[0-9a-fA-F]{64})\s+\*?(?<path>.+)$') {
        throw "Malformed checksum line: $line"
    }

    $expected = $Matches.hash.ToLowerInvariant()
    $path = $Matches.path.Trim()
    $candidate = $path

    if (-not (Test-Path -LiteralPath $candidate -PathType Leaf)) {
        $candidate = Split-Path -Leaf $path
    }
    if (-not (Test-Path -LiteralPath $candidate -PathType Leaf)) {
        $matches = Get-ChildItem -Recurse -File -Filter (Split-Path -Leaf $path)
        if ($matches.Count -eq 1) {
            $candidate = $matches[0].FullName
        }
    }
    if (-not (Test-Path -LiteralPath $candidate -PathType Leaf)) {
        throw "Missing artifact for checksum entry: $path"
    }

    $actual = (Get-FileHash -Algorithm SHA256 -LiteralPath $candidate).Hash.ToLowerInvariant()
    if ($actual -ne $expected) {
        throw "Checksum mismatch for $candidate`: expected $expected got $actual"
    }
    $resolved += [pscustomobject]@{ Path = $candidate; Expected = $expected }
}

Write-Host "level 1 ok: checksums verified"

function Get-ArtifactFiles {
    $resolved |
        Where-Object { $_.Path -notmatch '(^|[\\/])(SHA256SUMS|.*\.cdx\.json)$' } |
        Select-Object -ExpandProperty Path -Unique
}

if ([int]$Level -ge 2) {
    if (-not (Get-Command gh -ErrorAction SilentlyContinue)) {
        throw "Level 2 requires GitHub CLI (gh)"
    }
    foreach ($artifact in Get-ArtifactFiles) {
        gh attestation verify $artifact --repo $Repo
        if ($LASTEXITCODE -ne 0) {
            throw "GitHub attestation verification failed for $artifact"
        }
    }
    Write-Host "level 2 ok: GitHub attestations verified"
}

if ([int]$Level -ge 3) {
    $sboms = Get-ChildItem -Recurse -File -Filter "*.cdx.json"
    if ($sboms.Count -eq 0) {
        throw "Level 3 requires at least one CycloneDX SBOM (*.cdx.json)"
    }
    foreach ($sbom in $sboms) {
        $null = Get-Content -LiteralPath $sbom.FullName -Raw | ConvertFrom-Json
    }
    foreach ($artifact in Get-ArtifactFiles) {
        gh attestation verify $artifact --repo $Repo
        if ($LASTEXITCODE -ne 0) {
            throw "GitHub attestation verification failed for $artifact"
        }
    }
    Write-Host "level 3 ok: SBOM JSON present and attestations verified"
}

if ([int]$Level -ge 4) {
    if ([string]::IsNullOrWhiteSpace($env:OLYMPUS_RELEASE_PROOF_CMD)) {
        throw "Level 4 requires OLYMPUS_RELEASE_PROOF_CMD"
    }
    pwsh -NoLogo -NoProfile -Command $env:OLYMPUS_RELEASE_PROOF_CMD
    if ($LASTEXITCODE -ne 0) {
        throw "Olympus release commitment check failed"
    }
    Write-Host "level 4 ok: Olympus release commitment check passed"
}
