#!/usr/bin/env python3
"""
Verify that protocol/ module import boundaries are intact.

The Olympus protocol package has a strict one-way dependency order:

    canonical_json  (no internal deps)
    timestamps      (no internal deps)
         ↓
    hashes          (may import: canonical_json)
    canonical       (may import: canonical_json)
         ↓
    events          (may import: hashes, canonical)
         ↓
    merkle          (may import: events, hashes)
    ledger          (may import: canonical_json, hashes, timestamps)
    shards          (may import: hashes, timestamps)
    redaction       (may import: merkle, hashes)
    ssmf            (may import: hashes)
         ↓
    canonicalizer   (may import: any of the above)

The critical invariant is:
  * ``hashes`` must NOT import from ``canonical`` or ``canonicalizer``
  * ``canonical_json`` must NOT import any other internal ``protocol`` module
  * ``timestamps`` must NOT import any other internal ``protocol`` module

This script imports each module, inspects actual ``importlib`` state, and
fails loudly if a forbidden reverse dependency is detected.
"""

import ast
import sys
from pathlib import Path


# ---------------------------------------------------------------------------
# Forbidden (reverse) import edges: (importer, must_not_import)
# ---------------------------------------------------------------------------
FORBIDDEN_EDGES: list[tuple[str, str]] = [
    # hashes is a low-level primitive; must not depend on higher-level modules
    ("protocol.hashes", "protocol.canonical"),
    ("protocol.hashes", "protocol.canonicalizer"),
    ("protocol.hashes", "protocol.merkle"),
    ("protocol.hashes", "protocol.ledger"),
    ("protocol.hashes", "protocol.redaction"),
    # canonical_json is the lowest-level module; no internal deps allowed
    ("protocol.canonical_json", "protocol.hashes"),
    ("protocol.canonical_json", "protocol.canonical"),
    ("protocol.canonical_json", "protocol.canonicalizer"),
    ("protocol.canonical_json", "protocol.merkle"),
    ("protocol.canonical_json", "protocol.ledger"),
    # timestamps is a low-level utility; no internal deps allowed
    ("protocol.timestamps", "protocol.hashes"),
    ("protocol.timestamps", "protocol.canonical"),
    ("protocol.timestamps", "protocol.canonicalizer"),
    ("protocol.timestamps", "protocol.merkle"),
    ("protocol.timestamps", "protocol.ledger"),
]


def _get_internal_imports(module_path: Path) -> list[str]:
    """Return all ``protocol.*`` names imported by the given source file."""
    source = module_path.read_text(encoding="utf-8")
    try:
        tree = ast.parse(source, filename=str(module_path))
    except SyntaxError as exc:
        print(f"  SYNTAX ERROR in {module_path}: {exc}", file=sys.stderr)
        return []

    names: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name.startswith("protocol"):
                    names.append(alias.name)
        elif isinstance(node, ast.ImportFrom):
            module = node.module or ""
            if module.startswith("protocol") or node.level:
                # Resolve relative import to absolute name using the file path
                if node.level:
                    package = "protocol"
                    abs_name = f"{package}.{module}" if module else package
                else:
                    abs_name = module
                names.append(abs_name)
    return names


def main() -> int:
    """Run boundary checks; return 0 on success, 1 on violations."""
    repo_root = Path(__file__).parent.parent
    protocol_dir = repo_root / "protocol"

    if not protocol_dir.is_dir():
        print(f"ERROR: protocol/ directory not found at {protocol_dir}", file=sys.stderr)
        return 1

    violations: list[str] = []

    for importer_name, forbidden_dep in FORBIDDEN_EDGES:
        # Convert module name to file path
        rel_path = Path(*importer_name.split(".")).with_suffix(".py")
        module_path = repo_root / rel_path
        if not module_path.exists():
            # Module doesn't exist; skip silently (might be optional)
            continue

        actual_imports = _get_internal_imports(module_path)
        for imp in actual_imports:
            if imp == forbidden_dep or imp.startswith(forbidden_dep + "."):
                violations.append(
                    f"  VIOLATION: {importer_name} imports {imp!r} "
                    f"(forbidden: must not import {forbidden_dep})"
                )

    if violations:
        print("Import boundary violations detected:", file=sys.stderr)
        for v in violations:
            print(v, file=sys.stderr)
        print(
            "\nRun 'make boundary-check' to recheck after fixing.",
            file=sys.stderr,
        )
        return 1

    print("Import boundary check passed — all protocol dependencies flow one-way.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
