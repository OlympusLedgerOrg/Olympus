#!/usr/bin/env python3
"""
Unified Olympus CLI.

Currently supports:
    olympus canon <input.json> [--hash] [--format json|bytes|hex] [-o output]
"""

import argparse
import json
import os
import sys
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import urlopen


# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from protocol.canonical import canonicalize_document, document_to_bytes
from protocol.federation import FederationRegistry
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


def _default_registry_path() -> Path:
    """Return the repository's bundled federation registry path."""
    return Path(__file__).resolve().parent.parent / "examples" / "federation_registry.json"


def _load_registry(path: str | None) -> FederationRegistry:
    """Load the static federation registry from disk."""
    registry_path = Path(path) if path else _default_registry_path()
    return FederationRegistry.from_file(registry_path)


def _fetch_json(url: str) -> dict | list:
    """Fetch JSON from a federation node endpoint."""
    with urlopen(url, timeout=5) as response:
        return json.loads(response.read().decode("utf-8"))


def _cmd_node_list(args: argparse.Namespace) -> int:
    """List configured federation nodes from the static registry."""
    try:
        registry = _load_registry(args.registry)
    except Exception as exc:
        print(f"Error loading federation registry: {exc}", file=sys.stderr)
        return 1

    for node in registry.nodes:
        print(
            f"{node.node_id}\t{node.status}\t{node.operator}\t{node.jurisdiction}\t{node.endpoint}"
        )
    return 0


def _cmd_node_start(args: argparse.Namespace) -> int:
    """Start the Olympus API for a single node using local settings."""
    host = args.host
    port = args.port

    if args.node_id:
        try:
            registry = _load_registry(args.registry)
            node = registry.get_node(args.node_id)
        except Exception as exc:
            print(f"Error loading federation node config: {exc}", file=sys.stderr)
            return 1

        parsed = urlparse(node.endpoint)
        if parsed.hostname:
            host = parsed.hostname
        if parsed.port is not None:
            port = parsed.port

    database_url = os.environ.get("DATABASE_URL")
    if not database_url:
        print("DATABASE_URL is required", file=sys.stderr)
        return 1

    import uvicorn

    from api.app import app

    uvicorn.run(app, host=host, port=port)
    return 0


def _cmd_federation_status(args: argparse.Namespace) -> int:
    """Summarize registry quorum state and optionally query live shard roots."""
    try:
        registry = _load_registry(args.registry)
    except Exception as exc:
        print(f"Error loading federation registry: {exc}", file=sys.stderr)
        return 1

    active_nodes = registry.active_nodes()
    print("Federation Status")
    print()
    print(f"Nodes: {len(registry.nodes)}")
    print(f"Active: {len(active_nodes)}")
    print(f"Quorum: {registry.quorum_threshold()}")

    latest_root = "unknown"
    agreeing_nodes = 0
    if args.shard_id:
        roots: dict[str, int] = {}
        for node in active_nodes:
            try:
                shards = _fetch_json(f"{node.endpoint}/shards")
            except (HTTPError, URLError, TimeoutError, ValueError, json.JSONDecodeError):
                continue

            if not isinstance(shards, list):
                continue

            for shard in shards:
                if not isinstance(shard, dict) or shard.get("shard_id") != args.shard_id:
                    continue
                root = str(shard.get("latest_root", ""))
                if root:
                    roots[root] = roots.get(root, 0) + 1

        if roots:
            latest_root, agreeing_nodes = max(roots.items(), key=lambda item: item[1])

    print(f"Latest Root: {latest_root}")
    if args.shard_id:
        print(f"Shard: {args.shard_id}")
        print(f"Agreeing Nodes: {agreeing_nodes}")

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

    node_parser = subparsers.add_parser("node", help="Manage federation node configuration")
    node_subparsers = node_parser.add_subparsers(dest="node_command", required=True)

    node_list_parser = node_subparsers.add_parser("list", help="List federation nodes")
    node_list_parser.add_argument(
        "--registry",
        type=str,
        default=str(_default_registry_path()),
        help="Path to federation registry JSON",
    )

    node_start_parser = node_subparsers.add_parser("start", help="Start a local Olympus node")
    node_start_parser.add_argument("--node-id", type=str, help="Registry node id to start as")
    node_start_parser.add_argument(
        "--registry",
        type=str,
        default=str(_default_registry_path()),
        help="Path to federation registry JSON",
    )
    node_start_parser.add_argument("--host", default="127.0.0.1", help="Host to bind to")
    node_start_parser.add_argument("--port", type=int, default=8000, help="Port to bind to")

    federation_parser = subparsers.add_parser(
        "federation",
        help="Inspect static federation membership and quorum state",
    )
    federation_subparsers = federation_parser.add_subparsers(
        dest="federation_command",
        required=True,
    )
    federation_status_parser = federation_subparsers.add_parser(
        "status",
        help="Show federation node counts and optional live shard agreement",
    )
    federation_status_parser.add_argument(
        "--registry",
        type=str,
        default=str(_default_registry_path()),
        help="Path to federation registry JSON",
    )
    federation_status_parser.add_argument(
        "--shard-id",
        type=str,
        help="Optional shard id to query from configured node endpoints",
    )
    args = parser.parse_args()

    if args.command == "canon":
        return _cmd_canon(args)
    if args.command == "node":
        if args.node_command == "list":
            return _cmd_node_list(args)
        if args.node_command == "start":
            return _cmd_node_start(args)
    if args.command == "federation" and args.federation_command == "status":
        return _cmd_federation_status(args)

    parser.error(f"Unknown command: {args.command}")
    return 1


if __name__ == "__main__":
    sys.exit(main())
