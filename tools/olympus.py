#!/usr/bin/env python3
"""
Unified Olympus CLI.

Currently supports:
    olympus canon <input.json> [--hash] [--format json|bytes|hex] [-o output]
"""

import argparse
import json
import sys
from pathlib import Path

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from protocol.canonical import canonicalize_document, document_to_bytes
from protocol.hashes import hash_bytes


def _cmd_canon(args: argparse.Namespace) -> int:
    """Canonicalize a JSON document or emit its hash."""
    try:
        with open(args.input_file) as f:
            document = json.load(f)
    except FileNotFoundError:
        print(f"Error: File not found: {args.input_file}", file=sys.stderr)
        return 1
    except json.JSONDecodeError as exc:
        print(f"Error: Invalid JSON: {exc}", file=sys.stderr)
        return 1

    try:
        canonical = canonicalize_document(document)
        canonical_bytes = document_to_bytes(canonical)
    except Exception as exc:
        print(f"Error during canonicalization: {exc}", file=sys.stderr)
        return 1

    if args.hash:
        output = hash_bytes(canonical_bytes).hex()
    else:
        if args.format == "json":
            output = json.dumps(canonical, indent=2)
        elif args.format == "bytes":
            output = canonical_bytes.decode("utf-8")
        else:
            output = canonical_bytes.hex()

    if args.output:
        try:
            with open(args.output, "w") as f:
                f.write(output)
                if not args.hash:
                    f.write("\n")
        except Exception as exc:  # pragma: no cover - I/O errors
            print(f"Error writing output: {exc}", file=sys.stderr)
            return 1
    else:
        print(output)

    return 0


def main() -> int:
    parser = argparse.ArgumentParser(prog="olympus", description="Olympus protocol CLI")
    subparsers = parser.add_subparsers(dest="command", required=True)

    canon_parser = subparsers.add_parser("canon", help="Canonicalize JSON documents")
    canon_parser.add_argument("input_file", type=str, help="Path to input JSON document")
    canon_parser.add_argument("--output", "-o", type=str, help="Path to output file")
    canon_parser.add_argument("--hash", action="store_true", help="Output hash instead of document")
    canon_parser.add_argument(
        "--format",
        choices=["json", "bytes", "hex"],
        default="json",
        help="Output format when not hashing (default: json)",
    )
    args = parser.parse_args()

    if args.command == "canon":
        return _cmd_canon(args)

    parser.error(f"Unknown command: {args.command}")
    return 1


if __name__ == "__main__":
    sys.exit(main())
