#!/usr/bin/env python3
"""
Unified Olympus CLI.

Currently supports:
    olympus canon <input.json> [--hash] [--format json|bytes|hex] [-o output]
    olympus commit <file> --api-key <key> [--namespace ns] [--id id] [--api-url url]
    olympus ingest <file> [--generate-proof] [--verify] [--json]
"""

import argparse
import json
import os
import sys
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import Request, urlopen


# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from protocol.canonical import canonicalize_document, document_to_bytes
from protocol.federation import FederationRegistry
from protocol.hashes import hash_bytes
from tools.dataset_cli import build_dataset_parser, dispatch_dataset


def _read_file_bytes(path: str) -> bytes:
    """Read a file from disk and emit CLI-friendly errors on failure."""
    file_path = Path(path)
    try:
        return file_path.read_bytes()
    except FileNotFoundError as exc:
        raise ValueError(f"File not found: {path}") from exc
    except OSError as exc:
        raise ValueError(f"Error reading file: {exc}") from exc


def _normalize_api_url(api_url: str) -> str:
    """Validate the API base URL before sending network requests."""
    parsed = urlparse(api_url.rstrip("/"))
    if parsed.scheme not in {"http", "https"}:
        raise ValueError("api_url must use http or https")
    if not parsed.netloc:
        raise ValueError("api_url must include a hostname")
    return api_url.rstrip("/")


def _fetch_json_request(
    url: str, *, method: str = "GET", payload: dict | None = None, api_key: str = ""
) -> dict:
    """Send a JSON HTTP request and return the decoded JSON response."""
    data = None
    headers = {"Content-Type": "application/json"}
    if api_key:
        headers["X-API-Key"] = api_key
    if payload is not None:
        data = json.dumps(payload).encode("utf-8")
    request = Request(url, data=data, headers=headers, method=method)
    try:
        with urlopen(request, timeout=30) as response:  # noqa: S310
            return json.loads(response.read().decode("utf-8"))
    except HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")
        raise ValueError(f"Olympus API returned HTTP {exc.code}: {body}") from exc
    except URLError as exc:
        raise ValueError(f"Could not reach Olympus API at {url}: {exc.reason}") from exc
    except json.JSONDecodeError as exc:
        raise ValueError(f"Olympus API returned invalid JSON for {url}") from exc
    except Exception as exc:
        raise ValueError(f"Olympus API call failed: {exc}") from exc


def _commit_artifact(
    *, file_path: str, namespace: str, artifact_id: str, api_key: str, api_url: str
) -> tuple[str, dict]:
    """Hash a file and commit it to the Olympus ingest API."""
    file_bytes = _read_file_bytes(file_path)
    artifact_hash = hash_bytes(file_bytes).hex()
    normalized_api_url = _normalize_api_url(api_url)
    payload: dict[str, str] = {
        "artifact_hash": artifact_hash,
        "namespace": namespace,
        "id": artifact_id,
    }
    if api_key:
        payload["api_key"] = api_key

    endpoint = f"{normalized_api_url}/ingest/commit"
    result = _fetch_json_request(endpoint, method="POST", payload=payload, api_key=api_key)
    proof_id = result.get("proof_id", "")
    if not proof_id:
        raise ValueError("Olympus API returned no proof_id")
    return artifact_hash, result


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


def _cmd_commit(args: argparse.Namespace) -> int:
    """Compute the BLAKE3 hash of a file and commit it to the Olympus ledger."""
    try:
        _, result = _commit_artifact(
            file_path=args.file,
            namespace=args.namespace,
            artifact_id=args.id,
            api_key=args.api_key,
            api_url=args.api_url,
        )
        print(result["proof_id"])
        return 0
    except ValueError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1


def _cmd_ingest(args: argparse.Namespace) -> int:
    """Commit a file and optionally retrieve and verify its proof bundle."""
    artifact_id = args.id or Path(args.file).name
    try:
        artifact_hash, commit_result = _commit_artifact(
            file_path=args.file,
            namespace=args.namespace,
            artifact_id=artifact_id,
            api_key=args.api_key,
            api_url=args.api_url,
        )
        output: dict[str, object] = {
            "file": str(Path(args.file)),
            "artifact_hash": artifact_hash,
            "commit": commit_result,
        }
        api_url = _normalize_api_url(args.api_url)
        proof_id = str(commit_result["proof_id"])

        if args.generate_proof:
            output["proof"] = _fetch_json_request(
                f"{api_url}/ingest/records/{proof_id}/proof",
                api_key=args.api_key,
            )
        if args.verify:
            output["verification"] = _fetch_json_request(
                f"{api_url}/ingest/records/hash/{artifact_hash}/verify",
                api_key=args.api_key,
            )

        if args.json:
            print(json.dumps(output, indent=2))
        else:
            print(f"Committed: {args.file}")
            print(f"Proof ID: {proof_id}")
            print(f"Artifact Hash: {artifact_hash}")
            if "proof" in output:
                print("Generated proof bundle: yes")
            if "verification" in output:
                verification = output["verification"]
                assert isinstance(verification, dict)
                print(f"Server verification: {verification.get('merkle_proof_valid', False)}")
        return 0
    except ValueError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1


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
        payload = response.read().decode("utf-8")
        try:
            return json.loads(payload)
        except json.JSONDecodeError as exc:
            preview = payload[:120].replace("\n", " ")
            raise ValueError(f"Invalid JSON returned by {url}: {preview!r}") from exc


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

    # Import here so non-server CLI commands do not pay the FastAPI/uvicorn import cost.
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
            except (HTTPError, URLError, ValueError):
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

    commit_parser = subparsers.add_parser(
        "commit",
        help="Compute BLAKE3 hash of a file and commit it to the Olympus ledger",
    )
    commit_parser.add_argument("file", type=str, help="Path to the artifact file to commit")
    commit_parser.add_argument(
        "--api-key",
        type=str,
        default=os.environ.get("OLYMPUS_API_KEY", ""),
        help="Olympus API key (or set OLYMPUS_API_KEY env var)",
    )
    commit_parser.add_argument(
        "--namespace",
        type=str,
        default="default",
        help="Namespace for the artifact (e.g. 'github')",
    )
    commit_parser.add_argument(
        "--id",
        type=str,
        default="",
        help="Artifact identifier (e.g. 'org/repo/v1.0.0')",
    )
    commit_parser.add_argument(
        "--api-url",
        type=str,
        default=os.environ.get("OLYMPUS_API_URL", "http://localhost:8000"),
        help="Base URL of the Olympus API (or set OLYMPUS_API_URL env var)",
    )

    ingest_parser = subparsers.add_parser(
        "ingest",
        help="Commit a file and optionally retrieve and verify the resulting proof bundle",
    )
    ingest_parser.add_argument("file", type=str, help="Path to the document or artifact to ingest")
    ingest_parser.add_argument(
        "--api-key",
        type=str,
        default=os.environ.get("OLYMPUS_API_KEY", ""),
        help="Olympus API key (or set OLYMPUS_API_KEY env var)",
    )
    ingest_parser.add_argument(
        "--namespace",
        type=str,
        default="demo",
        help="Namespace for the artifact (default: demo)",
    )
    ingest_parser.add_argument(
        "--id",
        type=str,
        default="",
        help="Artifact identifier (defaults to the file name)",
    )
    ingest_parser.add_argument(
        "--api-url",
        type=str,
        default=os.environ.get("OLYMPUS_API_URL", "http://localhost:8000"),
        help="Base URL of the Olympus API (or set OLYMPUS_API_URL env var)",
    )
    ingest_parser.add_argument(
        "--generate-proof",
        action="store_true",
        help="Fetch the proof bundle after the commitment is recorded",
    )
    ingest_parser.add_argument(
        "--verify",
        action="store_true",
        help="Call the API verification endpoint for the committed content hash",
    )
    ingest_parser.add_argument(
        "--json",
        action="store_true",
        help="Emit the full ingest transcript as JSON",
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

    dataset_parser = subparsers.add_parser(
        "dataset",
        help="Dataset provenance tools (ADR-0010)",
    )
    build_dataset_parser(dataset_parser)

    args = parser.parse_args()

    if args.command == "canon":
        return _cmd_canon(args)
    if args.command == "commit":
        return _cmd_commit(args)
    if args.command == "ingest":
        return _cmd_ingest(args)
    if args.command == "node":
        if args.node_command == "list":
            return _cmd_node_list(args)
        if args.node_command == "start":
            return _cmd_node_start(args)
    if args.command == "federation" and args.federation_command == "status":
        return _cmd_federation_status(args)
    if args.command == "dataset":
        return dispatch_dataset(args)

    parser.error(f"Unknown command: {args.command}")
    return 1


if __name__ == "__main__":
    sys.exit(main())
