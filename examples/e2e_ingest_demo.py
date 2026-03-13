#!/usr/bin/env python3
"""Run an end-to-end Olympus ingest → proof retrieval → verification demo."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from urllib.request import Request, urlopen


sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


def _request_json(
    url: str, *, method: str = "GET", payload: dict | None = None, api_key: str = ""
) -> dict:
    """Send a JSON request and decode the JSON response."""
    data = None
    if payload is not None:
        data = json.dumps(payload).encode("utf-8")
    headers = {"Content-Type": "application/json"}
    if api_key:
        headers["X-API-Key"] = api_key
    request = Request(url, data=data, method=method, headers=headers)
    with urlopen(request, timeout=30) as response:  # noqa: S310
        return json.loads(response.read().decode("utf-8"))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("document", help="Path to the document or artifact to ingest")
    parser.add_argument(
        "--api-url",
        default="http://127.0.0.1:8000",
        help="Base URL for the Olympus API (default: http://127.0.0.1:8000)",
    )
    parser.add_argument("--api-key", default="", help="Optional Olympus API key")
    parser.add_argument("--namespace", default="examples", help="Artifact namespace")
    parser.add_argument("--id", dest="artifact_id", default="", help="Artifact identifier")
    args = parser.parse_args()

    document_path = Path(args.document)
    artifact_id = args.artifact_id or document_path.name

    file_bytes = document_path.read_bytes()

    from protocol.hashes import hash_bytes

    artifact_hash = hash_bytes(file_bytes).hex()
    commit = _request_json(
        f"{args.api_url.rstrip('/')}/ingest/commit",
        method="POST",
        payload={
            "artifact_hash": artifact_hash,
            "namespace": args.namespace,
            "id": artifact_id,
        },
        api_key=args.api_key,
    )
    proof = _request_json(
        f"{args.api_url.rstrip('/')}/ingest/records/{commit['proof_id']}/proof",
        api_key=args.api_key,
    )
    verification = _request_json(
        f"{args.api_url.rstrip('/')}/ingest/proofs/verify",
        method="POST",
        payload={
            "proof_id": proof["proof_id"],
            "content_hash": proof["content_hash"],
            "merkle_root": proof["merkle_root"],
            "merkle_proof": proof["merkle_proof"],
            "poseidon_root": proof["poseidon_root"],
        },
        api_key=args.api_key,
    )

    json.dump(
        {
            "file": str(document_path),
            "artifact_hash": artifact_hash,
            "commit": commit,
            "proof": proof,
            "verification": verification,
        },
        sys.stdout,
        indent=2,
    )
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
