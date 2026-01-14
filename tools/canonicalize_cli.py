#!/usr/bin/env python3
"""
Canonicalization CLI for Olympus

This tool canonicalizes documents according to Olympus protocol standards.
"""

import argparse
import json
import sys
from pathlib import Path


# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from protocol.canonical import canonicalize_document, document_to_bytes
from protocol.hashes import hash_bytes


def main() -> int:
    parser = argparse.ArgumentParser(description="Canonicalize documents for Olympus protocol")
    parser.add_argument("input_file", type=str, help="Path to input JSON document")
    parser.add_argument("--output", "-o", type=str, help="Path to output file (default: stdout)")
    parser.add_argument(
        "--hash", action="store_true", help="Output hash instead of canonical document"
    )
    parser.add_argument(
        "--format",
        choices=["json", "bytes", "hex"],
        default="json",
        help="Output format (default: json)",
    )

    args = parser.parse_args()

    # Read input document
    try:
        with open(args.input_file) as f:
            document = json.load(f)
    except FileNotFoundError:
        print(f"Error: File not found: {args.input_file}", file=sys.stderr)
        return 1
    except json.JSONDecodeError as e:
        print(f"Error: Invalid JSON: {e}", file=sys.stderr)
        return 1

    # Canonicalize
    try:
        canonical = canonicalize_document(document)
        canonical_bytes = document_to_bytes(canonical)
    except Exception as e:
        print(f"Error during canonicalization: {e}", file=sys.stderr)
        return 1

    # Compute output
    if args.hash:
        output = hash_bytes(canonical_bytes).hex()
    else:
        if args.format == "json":
            output = json.dumps(canonical, indent=2)
        elif args.format == "bytes":
            output = canonical_bytes.decode("utf-8")
        elif args.format == "hex":
            output = canonical_bytes.hex()

    # Write output
    if args.output:
        try:
            with open(args.output, "w") as f:
                f.write(output)
                if not args.hash:
                    f.write("\n")
            print(f"Output written to: {args.output}", file=sys.stderr)
        except Exception as e:
            print(f"Error writing output: {e}", file=sys.stderr)
            return 1
    else:
        print(output)

    return 0


if __name__ == "__main__":
    sys.exit(main())
