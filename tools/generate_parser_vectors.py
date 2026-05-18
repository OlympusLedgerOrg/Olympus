#!/usr/bin/env python3
"""Generate parser-output corpus for V3-O3 regression safety net.

Emits verifiers/test_vectors/parser_vectors.json — a fixed set of canonical
parser outputs with their ADR-0003 leaf hashes (parser_id + canonical_parser_version
bound into the SMT leaf).

Run:
    python tools/generate_parser_vectors.py

CI diff check:
    python tools/generate_parser_vectors.py --check

Exit 0 on success, 1 if the committed corpus has drifted from the reference
implementation output (``--check`` mode).
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import blake3 as b3


# Repo root so this script works when run from any CWD.
REPO_ROOT = Path(__file__).resolve().parent.parent
VECTORS_PATH = REPO_ROOT / "verifiers" / "test_vectors" / "parser_vectors.json"

sys.path.insert(0, str(REPO_ROOT))

from protocol.canonical import canonicalize_json  # noqa: E402
from protocol.hashes import global_key, leaf_hash, record_key  # noqa: E402


# ---------------------------------------------------------------------------
# Fixed test cases — DO NOT reorder; positions are part of the corpus contract.
# Add new cases at the end only.
# ---------------------------------------------------------------------------

_CASES: list[dict] = [
    # Case 0: plain FOIA record, docling parser
    {
        "description": "FOIA document — docling@2.3.1 parser, version 1",
        "document": {
            "id": "test-foia-001",
            "type": "foia_record",
            "title": "Budget allocation report FY-2024",
            "body": "All line items have been reviewed and approved.",
            "agency": "Dept. of Finance",
        },
        "record_type": "foia_record",
        "record_id": "test-foia-001",
        "version": 1,
        "shard_id": "shard-00",
        "parser_id": "docling@2.3.1",
        "canonical_parser_version": "v1",
    },
    # Case 1: raw-bytes parser (no text extraction)
    {
        "description": "Binary attachment — raw-bytes@1.0.0 parser",
        "document": {
            "id": "attach-001",
            "type": "attachment",
            "filename": "report.pdf",
            "byte_count": 204800,
            "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        },
        "record_type": "attachment",
        "record_id": "attach-001",
        "version": 1,
        "shard_id": "shard-01",
        "parser_id": "raw-bytes@1.0.0",
        "canonical_parser_version": "v1",
    },
    # Case 2: unicode-heavy record, ensures NFC normalisation is stable
    {
        "description": "Unicode content — NFC normalisation stability",
        "document": {
            "id": "unicode-001",
            "type": "foia_record",
            "title": "Café résumé naïve façade",
            "body": "The résumé was reviewed by the Ångström committee.",
            "tags": ["naïve", "cliché", "piñata"],
        },
        "record_type": "foia_record",
        "record_id": "unicode-001",
        "version": 1,
        "shard_id": "shard-00",
        "parser_id": "docling@2.3.1",
        "canonical_parser_version": "v1",
    },
    # Case 3: version bump — same record_id, version 2
    {
        "description": "Version bump — same record_id as case 0, version 2",
        "document": {
            "id": "test-foia-001",
            "type": "foia_record",
            "title": "Budget allocation report FY-2024 (revised)",
            "body": "Revision: line item 7 corrected.",
            "agency": "Dept. of Finance",
        },
        "record_type": "foia_record",
        "record_id": "test-foia-001",
        "version": 2,
        "shard_id": "shard-00",
        "parser_id": "docling@2.3.1",
        "canonical_parser_version": "v1",
    },
    # Case 4: parser version upgrade — different canonical_parser_version
    {
        "description": "Parser version upgrade — canonical_parser_version v2",
        "document": {
            "id": "test-foia-002",
            "type": "foia_record",
            "title": "Infrastructure audit Q3-2025",
            "body": "Summary: all systems nominal.",
        },
        "record_type": "foia_record",
        "record_id": "test-foia-002",
        "version": 1,
        "shard_id": "shard-00",
        "parser_id": "docling@3.0.0",
        "canonical_parser_version": "v2",
    },
    # Case 5: empty body (edge case)
    {
        "description": "Empty body field — edge case for canonical JSON",
        "document": {
            "id": "empty-001",
            "type": "foia_record",
            "title": "Intentionally empty",
            "body": "",
        },
        "record_type": "foia_record",
        "record_id": "empty-001",
        "version": 1,
        "shard_id": "shard-02",
        "parser_id": "raw-bytes@1.0.0",
        "canonical_parser_version": "v1",
    },
    # Case 6: numeric and boolean fields — JCS key ordering
    {
        "description": "Mixed types — JCS key ordering across numeric/bool/string",
        "document": {
            "z_last": True,
            "a_first": 42,
            "m_middle": "hello",
            "id": "jcs-001",
            "type": "foia_record",
        },
        "record_type": "foia_record",
        "record_id": "jcs-001",
        "version": 1,
        "shard_id": "shard-03",
        "parser_id": "docling@2.3.1",
        "canonical_parser_version": "v1",
    },
]


def _compute_vector(case: dict) -> dict:
    """Compute the full parser output vector for one test case."""
    doc = case["document"]
    raw_canonical = canonicalize_json(doc)
    if isinstance(raw_canonical, str):
        canonical_bytes = raw_canonical.encode("utf-8")
    else:
        canonical_bytes = raw_canonical

    value_hash = b3.blake3(canonical_bytes).digest()
    rk = record_key(case["record_type"], case["record_id"], case["version"])
    gk = global_key(case["shard_id"], rk)
    lh = leaf_hash(gk, value_hash, case["parser_id"], case["canonical_parser_version"])

    return {
        "description": case["description"],
        "input": {
            "document": doc,
            "record_type": case["record_type"],
            "record_id": case["record_id"],
            "version": case["version"],
            "shard_id": case["shard_id"],
            "parser_id": case["parser_id"],
            "canonical_parser_version": case["canonical_parser_version"],
        },
        "output": {
            "canonical_json": canonical_bytes.decode("utf-8"),
            "value_hash_hex": value_hash.hex(),
            "record_key_hex": rk.hex(),
            "global_key_hex": gk.hex(),
            "leaf_hash_hex": lh.hex(),
        },
    }


def generate() -> dict:
    return {
        "version": "1",
        "description": (
            "Olympus parser-output regression corpus (V3-O3). "
            "Each vector captures canonical JSON output + ADR-0003 leaf hash "
            "(parser_id + canonical_parser_version bound via global_key → leaf_hash). "
            "Regenerated by: python tools/generate_parser_vectors.py"
        ),
        "cases": [_compute_vector(c) for c in _CASES],
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--check",
        action="store_true",
        help="Diff against committed corpus; exit 1 on drift.",
    )
    args = parser.parse_args()

    fresh = generate()

    if args.check:
        if not VECTORS_PATH.exists():
            print(
                f"ERROR: {VECTORS_PATH} does not exist. Run without --check to generate it first.",
                file=sys.stderr,
            )
            sys.exit(1)
        committed = json.loads(VECTORS_PATH.read_text(encoding="utf-8"))
        if committed != fresh:
            print(
                "ERROR: parser_vectors.json has drifted from the reference "
                "implementation.\nRun `python tools/generate_parser_vectors.py` "
                "to regenerate and commit the updated corpus.",
                file=sys.stderr,
            )
            # Show first differing case for quick diagnosis
            for i, (a, b) in enumerate(zip(committed.get("cases", []), fresh.get("cases", []))):
                if a != b:
                    print(f"  First drift at case {i}: {a['description']}", file=sys.stderr)
                    break
            sys.exit(1)
        print(f"OK — parser_vectors.json matches reference ({len(fresh['cases'])} cases)")
    else:
        VECTORS_PATH.write_text(
            json.dumps(fresh, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
        print(f"Written {len(fresh['cases'])} cases -> {VECTORS_PATH}")


if __name__ == "__main__":
    main()
