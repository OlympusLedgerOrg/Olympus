#!/usr/bin/env python3
"""Append a record to a shard (in-memory) for quick demos."""

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from app.state import OlympusState  # noqa: E402


def main():
    parser = argparse.ArgumentParser(description="Append a record to a shard (demo)")
    parser.add_argument("--shard", required=True, help="shard id")
    parser.add_argument("--record-type", required=True)
    parser.add_argument("--record-id", required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--value", required=True, help="JSON string payload")
    args = parser.parse_args()

    try:
        value = json.loads(args.value)
    except json.JSONDecodeError as exc:
        print(f"invalid JSON payload: {exc}", file=sys.stderr)
        return 1

    state = OlympusState()
    header = state.append_record(args.shard, args.record_type, args.record_id, args.version, value)
    print(json.dumps({"header_hash": header.header_hash, "root": header.root}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
