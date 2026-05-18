# pre-compact.ps1 — runs before Claude compacts the conversation.
# Reads memory + todos and emits a structured work summary so the context
# survives compaction intact.

$memDir = "$env:USERPROFILE\.claude\projects\C--Users-1983a-Downloads-Olympus\memory"
$repoRoot = "C:\Users\1983a\Downloads\Olympus"

$lines = @()
$lines += "=== OLYMPUS WORK CONTEXT (pre-compact snapshot) ==="
$lines += "Repo   : $repoRoot"
$lines += "Branch : $(git -C $repoRoot rev-parse --abbrev-ref HEAD 2>$null)"
$lines += "Time   : $(Get-Date -Format 'yyyy-MM-dd HH:mm')"
$lines += ""

# Active memory entries
$memIndex = Join-Path $memDir "MEMORY.md"
if (Test-Path $memIndex) {
    $lines += "--- Active memory ---"
    $lines += Get-Content $memIndex | Where-Object { $_ -match "^\-" }
    $lines += ""
}

# Recent git work (last 5 commits on this branch vs main)
$lines += "--- Recent commits ---"
$commits = git -C $repoRoot log --oneline -5 2>$null
if ($commits) { $lines += $commits } else { $lines += "(none)" }
$lines += ""

# Staged / modified files
$lines += "--- Dirty files ---"
$dirty = git -C $repoRoot status --short 2>$null
if ($dirty) { $lines += $dirty } else { $lines += "(clean)" }
$lines += ""

# Key Olympus subsystems touched (inferred from dirty list)
$subsystems = @()
if ($dirty -match "src-tauri") { $subsystems += "Tauri/Rust (src-tauri/)" }
if ($dirty -match "proofs/circuits") { $subsystems += "ZK circuits (proofs/circuits/)" }
if ($dirty -match "proofs/keys") { $subsystems += "Verification keys (proofs/keys/)" }
if ($dirty -match "api/") { $subsystems += "Python API (api/)" }
if ($dirty -match "protocol/") { $subsystems += "Protocol layer (protocol/)" }
if ($dirty -match "storage/") { $subsystems += "Storage layer (storage/)" }
if ($dirty -match "app/public-ui") { $subsystems += "React frontend (app/public-ui/)" }
if ($dirty -match "alembic/") { $subsystems += "DB migrations (alembic/)" }

if ($subsystems.Count -gt 0) {
    $lines += "--- Subsystems in flight ---"
    $lines += $subsystems
    $lines += ""
}

$lines += "=== end pre-compact snapshot ==="

$summary = $lines -join "`n"

# Output JSON that Claude Code injects into the compaction context
@{
    systemMessage = $summary
} | ConvertTo-Json -Compress
