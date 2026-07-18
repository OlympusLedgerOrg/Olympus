# Olympus judge walkthrough

This walkthrough tests Olympus's OpenAI Build Week extension without compiling
the desktop application or installing PostgreSQL, Node.js, Tauri, or ZK tools.
The standalone binary is network-free and creates one local SQLite file.

Expected time: under five minutes.

## 1. Download

Open the
[Build Week judge-demo release](https://github.com/OlympusLedgerOrg/Olympus/releases/tag/build-week-2026-demo)
and download the binary for your platform plus `SHA256SUMS`:

| Platform | Asset |
|---|---|
| Windows 10/11 x64 | `olympus-smt-demo-windows-x64.exe` |
| Ubuntu/Linux x64 | `olympus-smt-demo-linux-x64` |
| macOS Apple Silicon | `olympus-smt-demo-macos-arm64` |

The release is produced by
[`.github/workflows/build-week-demo.yml`](.github/workflows/build-week-demo.yml)
from the commit recorded in the binary's JSON output.

## 2. Verify and run

### Windows PowerShell

```powershell
$binary = "olympus-smt-demo-windows-x64.exe"
$line = Get-Content .\SHA256SUMS | Where-Object { $_ -match "  $([regex]::Escape($binary))$" }
if (@($line).Count -ne 1) { throw "Expected one checksum entry for $binary" }
$expected = ($line -split '\s+')[0]
$actual = (Get-FileHash ".\$binary" -Algorithm SHA256).Hash
if ($actual -ne $expected) { throw "SHA-256 mismatch for $binary" }
.\olympus-smt-demo-windows-x64.exe --database olympus-demo.sqlite --reset
```

### Linux

```bash
grep '  olympus-smt-demo-linux-x64$' SHA256SUMS | sha256sum --check --strict -
chmod +x olympus-smt-demo-linux-x64
./olympus-smt-demo-linux-x64 --database olympus-demo.sqlite --reset
```

### macOS Apple Silicon

```bash
grep '  olympus-smt-demo-macos-arm64$' SHA256SUMS | shasum -a 256 --check -
chmod +x olympus-smt-demo-macos-arm64
xattr -d com.apple.quarantine olympus-smt-demo-macos-arm64 2>/dev/null || true
./olympus-smt-demo-macos-arm64 --database olympus-demo.sqlite --reset
```

The `--reset` flag deletes only the named demo database and its SQLite sidecar
files before starting. Omit it to reopen and reverify an existing demo file.

## 3. Expected result

The process exits with status zero and prints a JSON report ending with:

```json
{
  "checks": {
    "durability_reopen": true,
    "existence_proof": true,
    "leaf_and_node_rollback_atomic": true,
    "non_existence_proof": true,
    "stale_reader_snapshot_refresh": true,
    "write_once_batch_rollback": true
  },
  "status": "PASS"
}
```

The report also includes the exact build commit, database path, deterministic
Merkle root, backend, and inserted-leaf count.

## What the checks prove

| Check | Demonstrated behavior |
|---|---|
| Existence proof | An inserted leaf has an offline-verifiable path to the durable root |
| Non-existence proof | An absent key has an offline-verifiable sparse-tree proof |
| Leaf/node rollback | Staged rows in both physical tables disappear together on rollback |
| Stale-reader refresh | A handle opened before another commit proves against the newer stable snapshot |
| Write-once batch rollback | One conflicting re-commit aborts the entire batch, including a new sibling leaf |
| Durable reopen | A new connection reconstructs the same root and retrieves the committed value |

These focused backend checks do not establish shard authorization, issuer or
signature authenticity, integrity against an adversarial database, or
concurrent multi-writer serialization. Those properties require the controls
and assumptions described in the [project threat model](docs/threat-model.md);
the demo proves only the behaviors listed above.

## Build-from-source fallback

The prebuilt release is the primary testing path. To independently reproduce
it with Rust 1.94 or newer:

```bash
cargo run --locked --release -p olympus-desktop --no-default-features \
  --bin olympus-smt-demo -- --database olympus-demo.sqlite --reset
```

## Cleanup

After testing, remove `olympus-demo.sqlite`. The demo does not create accounts,
contact a network service, or write outside the selected database path and
ordinary operating-system temporary/build locations.

## Full-project context

Olympus is a Tauri desktop system for verifiable sensitive records. The Build
Week feature demonstrated here is its transaction-bound SMT storage layer. The
desktop application continues to use embedded PostgreSQL for broader
application state; SQLite support is deliberately scoped to the SMT backend.
See [`BUILD_WEEK.md`](BUILD_WEEK.md) for the provenance boundary and exact diff.
