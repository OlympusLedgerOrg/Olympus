#!/usr/bin/env python3
"""Generate or verify proofs using the in-memory state."""

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from app.state import OlympusState  # noqa: E402
from protocol.hashes import record_key  # noqa: E402
from protocol.ssmf import verify_proof as verify_sparse_proof, SparseMerkleProof, ProofNode  # noqa: E402


def main():
    parser = argparse.ArgumentParser(description="Produce or verify sparse Merkle proofs")
    sub = parser.add_subparsers(dest="cmd", required=True)

    gen = sub.add_parser("existence", help="Generate existence proof from in-memory state (demo)")
    gen.add_argument("--shard", required=True)
    gen.add_argument("--record-type", required=True)
    gen.add_argument("--record-id", required=True)
    gen.add_argument("--version", required=True)
    gen.add_argument("--value", required=True, help="JSON payload")

    verify = sub.add_parser("verify", help="Verify a proof JSON against a root/key")
    verify.add_argument("--root", required=True)
    verify.add_argument("--key", required=True, help="hex-encoded key")
    verify.add_argument("--proof-file", required=True)
    verify.add_argument("--value-hash", help="hex-encoded value hash (optional)")

    args = parser.parse_args()

    if args.cmd == "existence":
        import json as pyjson

        value = pyjson.loads(args.value)
        state = OlympusState()
        state.append_record(args.shard, args.record_type, args.record_id, args.version, value)
        key = record_key(args.record_type, args.record_id, args.version)
        proof = state.proof_existence(args.shard, key)
        print(json.dumps(proof.to_dict(), indent=2))
        return 0

    if args.cmd == "verify":
        with open(args.proof_file, "r") as f:
            proof_payload = json.load(f)
        proof = SparseMerkleProof(
            key=bytes.fromhex(proof_payload["key"]),
            leaf_hash=bytes.fromhex(proof_payload["leaf_hash"]),
            siblings=[ProofNode(hash=bytes.fromhex(item["hash"]), is_right=item["is_right"]) for item in proof_payload["siblings"]],
            exists=proof_payload["exists"],
            value_hash=bytes.fromhex(proof_payload["value_hash"]) if proof_payload.get("value_hash") else None,
        )
        ok = verify_sparse_proof(
            bytes.fromhex(args.root),
            bytes.fromhex(args.key),
            proof,
            bytes.fromhex(args.value_hash) if args.value_hash else None,
        )
        print(json.dumps({"valid": ok}))
        return 0 if ok else 1

    return 1


if __name__ == "__main__":
    sys.exit(main())
