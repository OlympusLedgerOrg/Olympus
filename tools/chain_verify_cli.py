#!/usr/bin/env python3
"""
Chain verification and diagnostics CLI for Olympus operators.

Provides tools for verifying ledger chain integrity, inspecting entries,
and diagnosing problems without requiring SQL knowledge.

Usage:
    # Verify a ledger chain exported as JSON
    python tools/chain_verify_cli.py verify ledger_export.json

    # Show summary of a ledger export
    python tools/chain_verify_cli.py inspect ledger_export.json

    # Check a specific entry hash
    python tools/chain_verify_cli.py lookup ledger_export.json <entry_hash>

    # Export a diagnostic report
    python tools/chain_verify_cli.py diagnose ledger_export.json
"""

import argparse
import json
import sys
from pathlib import Path


# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from protocol.canonical_json import canonical_json_bytes
from protocol.hashes import _SEP, LEDGER_PREFIX, blake3_hash
from protocol.ledger import Ledger, LedgerEntry


def _load_ledger(ledger_file: str) -> Ledger:
    """Load a ledger from a JSON export file.

    Args:
        ledger_file: Path to the ledger JSON file.

    Returns:
        Populated Ledger instance.

    Raises:
        SystemExit: On file or format errors.
    """
    path = Path(ledger_file)
    if not path.exists():
        print(f"Error: File not found: {ledger_file}", file=sys.stderr)
        sys.exit(1)

    try:
        with path.open() as f:
            data = json.load(f)
    except json.JSONDecodeError as exc:
        print(f"Error: Invalid JSON in {ledger_file}: {exc}", file=sys.stderr)
        sys.exit(1)

    entries_data = data.get("entries", data if isinstance(data, list) else [])
    if not entries_data:
        print(f"Error: No entries found in {ledger_file}", file=sys.stderr)
        sys.exit(1)

    ledger = Ledger()
    for entry_data in entries_data:
        entry = LedgerEntry.from_dict(entry_data)
        ledger.entries.append(entry)

    return ledger


def cmd_verify(args: argparse.Namespace) -> int:
    """Verify the integrity of a ledger chain.

    Checks:
    - Genesis entry has empty previous hash
    - Each entry hash is correctly computed
    - Chain linkage is unbroken (prev_hash matches)
    """
    ledger = _load_ledger(args.ledger_file)
    entries = ledger.entries

    print(f"Verifying ledger chain ({len(entries)} entries)...")
    errors: list[str] = []

    # Check genesis
    if entries and entries[0].prev_entry_hash != "":
        errors.append("GENESIS ERROR: First entry has non-empty prev_entry_hash")

    for i, entry in enumerate(entries):
        # Recompute entry hash
        payload = {
            "ts": entry.ts,
            "record_hash": entry.record_hash,
            "shard_id": entry.shard_id,
            "shard_root": entry.shard_root,
            "canonicalization": entry.canonicalization,
            "prev_entry_hash": entry.prev_entry_hash,
            "poseidon_root": entry.poseidon_root,
        }
        normalized_certificate = ledger._canonicalize_quorum_certificate(
            entry.federation_quorum_certificate
        )
        if normalized_certificate is not None:
            payload["federation_quorum_certificate"] = normalized_certificate

        if entry.poseidon_root is not None:
            poseidon_int = int(entry.poseidon_root)
            poseidon_bytes = poseidon_int.to_bytes(32, byteorder="big")
        else:
            poseidon_bytes = b""

        expected_hash = blake3_hash([LEDGER_PREFIX, canonical_json_bytes(payload), _SEP, poseidon_bytes]).hex()

        if entry.entry_hash != expected_hash:
            errors.append(
                f"HASH MISMATCH at entry {i}: "
                f"expected {expected_hash[:16]}..., got {entry.entry_hash[:16]}..."
            )

        # Chain linkage
        if i > 0 and entry.prev_entry_hash != entries[i - 1].entry_hash:
            errors.append(
                f"CHAIN BREAK at entry {i}: "
                f"prev_entry_hash {entry.prev_entry_hash[:16]}... "
                f"does not match entry {i - 1} hash {entries[i - 1].entry_hash[:16]}..."
            )

    if errors:
        print(f"\n✗ Chain verification FAILED ({len(errors)} error(s)):", file=sys.stderr)
        for error in errors:
            print(f"  - {error}", file=sys.stderr)
        return 1
    else:
        print(f"✓ Ledger chain is VALID ({len(entries)} entries verified)")
        return 0


def cmd_inspect(args: argparse.Namespace) -> int:
    """Show a summary of the ledger."""
    ledger = _load_ledger(args.ledger_file)
    entries = ledger.entries

    print(f"Ledger Summary ({len(entries)} entries)")
    print("=" * 60)

    if not entries:
        print("  (empty ledger)")
        return 0

    # Shard distribution
    shards: dict[str, int] = {}
    for entry in entries:
        shards[entry.shard_id] = shards.get(entry.shard_id, 0) + 1

    print(f"  First entry:  {entries[0].ts}")
    print(f"  Last entry:   {entries[-1].ts}")
    print(f"  Total shards: {len(shards)}")
    print()
    print("  Shard distribution:")
    for shard_id, count in sorted(shards.items()):
        print(f"    {shard_id}: {count} entries")

    # Chain status
    is_valid = ledger.verify_chain()
    print()
    print(f"  Chain integrity: {'✓ VALID' if is_valid else '✗ INVALID'}")

    return 0


def cmd_lookup(args: argparse.Namespace) -> int:
    """Look up a specific entry by hash."""
    ledger = _load_ledger(args.ledger_file)
    entry_hash = args.entry_hash

    entry = ledger.get_entry(entry_hash)
    if entry is None:
        # Try prefix match
        matches = [e for e in ledger.entries if e.entry_hash.startswith(entry_hash)]
        if len(matches) == 1:
            entry = matches[0]
        elif len(matches) > 1:
            print(f"Ambiguous hash prefix '{entry_hash}': {len(matches)} matches")
            for m in matches:
                print(f"  {m.entry_hash}")
            return 1
        else:
            print(f"Entry not found: {entry_hash}", file=sys.stderr)
            return 1

    print(json.dumps(entry.to_dict(), indent=2))
    return 0


def cmd_diagnose(args: argparse.Namespace) -> int:
    """Run diagnostics on the ledger and produce a report."""
    ledger = _load_ledger(args.ledger_file)
    entries = ledger.entries

    report: dict[str, object] = {
        "file": args.ledger_file,
        "total_entries": len(entries),
        "chain_valid": ledger.verify_chain(),
        "shards": {},
        "issues": [],
    }

    shards: dict[str, list[str]] = {}
    for entry in entries:
        shards.setdefault(entry.shard_id, []).append(entry.ts)

    shard_summary = {}
    for shard_id, timestamps in shards.items():
        shard_summary[shard_id] = {
            "count": len(timestamps),
            "first": timestamps[0],
            "last": timestamps[-1],
        }
    report["shards"] = shard_summary

    # Check for issues
    issues = []
    if entries and entries[0].prev_entry_hash != "":
        issues.append("Genesis entry has non-empty prev_entry_hash")

    for i in range(1, len(entries)):
        if entries[i].prev_entry_hash != entries[i - 1].entry_hash:
            issues.append(f"Chain break between entries {i - 1} and {i}")

    # Check for duplicate entry hashes
    seen_hashes: set[str] = set()
    for i, entry in enumerate(entries):
        if entry.entry_hash in seen_hashes:
            issues.append(f"Duplicate entry hash at index {i}: {entry.entry_hash[:16]}...")
        seen_hashes.add(entry.entry_hash)

    report["issues"] = issues

    print(json.dumps(report, indent=2))

    if issues:
        print(f"\n⚠ {len(issues)} issue(s) found", file=sys.stderr)
        return 1
    else:
        print("\n✓ No issues found")
        return 0


def main() -> int:
    """CLI entry point."""
    parser = argparse.ArgumentParser(description="Olympus chain verification and diagnostics CLI")
    subparsers = parser.add_subparsers(dest="command", help="Command to run")

    # verify
    verify_parser = subparsers.add_parser("verify", help="Verify ledger chain integrity")
    verify_parser.add_argument("ledger_file", help="Path to ledger JSON export")

    # inspect
    inspect_parser = subparsers.add_parser("inspect", help="Show ledger summary")
    inspect_parser.add_argument("ledger_file", help="Path to ledger JSON export")

    # lookup
    lookup_parser = subparsers.add_parser("lookup", help="Look up an entry by hash")
    lookup_parser.add_argument("ledger_file", help="Path to ledger JSON export")
    lookup_parser.add_argument("entry_hash", help="Entry hash (or prefix)")

    # diagnose
    diagnose_parser = subparsers.add_parser("diagnose", help="Run diagnostics and produce a report")
    diagnose_parser.add_argument("ledger_file", help="Path to ledger JSON export")

    args = parser.parse_args()
    if not args.command:
        parser.print_help()
        return 1

    commands = {
        "verify": cmd_verify,
        "inspect": cmd_inspect,
        "lookup": cmd_lookup,
        "diagnose": cmd_diagnose,
    }

    return commands[args.command](args)


if __name__ == "__main__":
    sys.exit(main())
