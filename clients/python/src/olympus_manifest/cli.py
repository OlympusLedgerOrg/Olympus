"""Console entry point: ``olympus-py``.

A small command surface for pipelines that live in Python. The full builder is
the Rust ``olympus`` CLI; this focuses on verifying proofs, hashing files, and
talking to a node.
"""

from __future__ import annotations

import argparse
import json
import sys

from .client import OlympusClient, hash_file, scan
from .proof import verify


def _verify(args: argparse.Namespace) -> int:
    with open(args.proof) as f:
        bundle = json.load(f)
    with open(args.manifest) as f:
        manifest = json.load(f)
    if bundle.get("dataset_id") != manifest.get("dataset_id") or bundle.get(
        "version"
    ) != manifest.get("version"):
        print("warning: proof and manifest target different dataset/version", file=sys.stderr)
    verdict = verify(bundle, bytes.fromhex(manifest["manifest_root"]))
    label = bundle.get("kind", "?").upper()
    if verdict.is_valid:
        rel = "is committed in" if bundle["kind"] == "inclusion" else "is absent from"
        print(
            f"VALID {label}: {bundle['shard_id']}/{bundle['record_id']} {rel} "
            f"dataset '{manifest['dataset_id']}' v{manifest['version']}"
        )
        return 0
    print(f"INVALID {label}: {verdict.value}")
    return 1


def _hash(args: argparse.Namespace) -> int:
    digest, size = hash_file(args.file)
    print(f"{digest}  {size}  {args.file}")
    return 0


def _scan(args: argparse.Namespace) -> int:
    index = scan(args.data, shard=args.shard, shard_from_subdir=args.shard_from_subdir)
    out = json.dumps(index, indent=2)
    if args.out:
        with open(args.out, "w") as f:
            f.write(out)
        print(f"record index ({sum(len(s['records']) for s in index['shards'])} records) -> {args.out}", file=sys.stderr)
    else:
        print(out)
    return 0


def _fetch(args: argparse.Namespace) -> int:
    client = OlympusClient(args.server)
    print(json.dumps(client.fetch_proof(args.hash), indent=2))
    return 0


def _commit(args: argparse.Namespace) -> int:
    client = OlympusClient(args.server, api_key=args.api_key)
    print(json.dumps(client.commit(args.manifest, shard=args.shard), indent=2))
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="olympus-py", description="Olympus manifest client")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("verify", help="verify a record proof against a manifest")
    p.add_argument("--proof", required=True)
    p.add_argument("--manifest", required=True)
    p.set_defaults(func=_verify)

    p = sub.add_parser("hash", help="BLAKE3-hash a file")
    p.add_argument("file")
    p.set_defaults(func=_hash)

    p = sub.add_parser("scan", help="hash a directory into a record index")
    p.add_argument("--data", required=True)
    p.add_argument("--shard", default="files")
    p.add_argument("--shard-from-subdir", action="store_true")
    p.add_argument("--out")
    p.set_defaults(func=_scan)

    p = sub.add_parser("fetch", help="pull a committed blob's ledger proof")
    p.add_argument("--server", required=True)
    p.add_argument("--hash", required=True)
    p.set_defaults(func=_fetch)

    p = sub.add_parser("commit", help="POST a manifest to a node")
    p.add_argument("--manifest", required=True)
    p.add_argument("--server", required=True)
    p.add_argument("--shard", default="files")
    p.add_argument("--api-key")
    p.set_defaults(func=_commit)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
