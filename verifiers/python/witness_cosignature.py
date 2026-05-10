"""Python witness-cosigned envelope verifier scaffold."""

from __future__ import annotations

import json
from pathlib import Path

from api.transparency.witness import WitnessCosignature, verify_cosignature


def verify_witness_envelope(path: str | Path) -> bool:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    root = bytes.fromhex(data["root_hash"])
    threshold = int(data.get("witness_threshold", 2))
    signatures = [WitnessCosignature(**item) for item in data["witness_cosignatures"]]
    return verify_cosignature(root, signatures, threshold=threshold)


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument("vector_path")
    args = parser.parse_args()
    raise SystemExit(0 if verify_witness_envelope(args.vector_path) else 1)
