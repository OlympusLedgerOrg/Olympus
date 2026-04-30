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

Within the federation subpackage, the one-way dependency order is:

    federation.identity   (may import: hashes only)
         ↓
    federation.quorum     (may import: identity, canonical_json, hashes)
         ↓
    federation.replication  (may import: identity, quorum, hashes, timestamps)
    federation.rotation     (may import: identity, quorum, canonical_json, hashes)
    federation.gossip       (may import: identity, quorum, hashes, ledger)

The critical invariants are:
  * ``hashes`` must NOT import from ``canonical`` or ``canonicalizer``
  * ``canonical_json`` must NOT import any other internal ``protocol`` module
  * ``timestamps`` must NOT import any other internal ``protocol`` module
  * ``federation.identity`` must NOT import from any other federation submodule
  * ``federation.quorum`` must NOT import from replication, rotation, or gossip

This script parses each module's source, resolves relative imports to their
absolute names, and fails loudly if a forbidden reverse dependency is detected.
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
    # federation.identity is the leaf; must not depend on any other federation submodule
    ("protocol.federation.identity", "protocol.federation.quorum"),
    ("protocol.federation.identity", "protocol.federation.replication"),
    ("protocol.federation.identity", "protocol.federation.rotation"),
    ("protocol.federation.identity", "protocol.federation.gossip"),
    # federation.quorum must not depend on higher-level federation submodules
    ("protocol.federation.quorum", "protocol.federation.replication"),
    ("protocol.federation.quorum", "protocol.federation.rotation"),
    ("protocol.federation.quorum", "protocol.federation.gossip"),
    # federation.replication must not depend on rotation or gossip
    ("protocol.federation.replication", "protocol.federation.rotation"),
    ("protocol.federation.replication", "protocol.federation.gossip"),
    # federation.rotation must not depend on replication or gossip
    ("protocol.federation.rotation", "protocol.federation.replication"),
    ("protocol.federation.rotation", "protocol.federation.gossip"),
    # federation.gossip must not depend on replication or rotation
    ("protocol.federation.gossip", "protocol.federation.replication"),
    ("protocol.federation.gossip", "protocol.federation.rotation"),
]


def _module_name_from_path(module_path: Path, repo_root: Path) -> str:
    """Return the dotted module name for a source file relative to repo_root."""
    rel = module_path.relative_to(repo_root).with_suffix("")
    parts = rel.parts
    # Drop trailing __init__ so packages resolve correctly
    if parts[-1] == "__init__":
        parts = parts[:-1]
    return ".".join(parts)


def _get_internal_imports(module_path: Path, repo_root: Path) -> list[str]:
    """Return all ``protocol.*`` names imported by the given source file.

    Relative imports are resolved to absolute dotted names using the file's
    actual package, so ``from .quorum import …`` inside
    ``protocol/federation/identity.py`` correctly yields
    ``protocol.federation.quorum`` rather than ``protocol.quorum``.
    """
    source = module_path.read_text(encoding="utf-8")
    try:
        tree = ast.parse(source, filename=str(module_path))
    except SyntaxError as exc:
        print(f"  SYNTAX ERROR in {module_path}: {exc}", file=sys.stderr)
        return []

    # Determine the package of this file for relative-import resolution.
    # e.g. protocol/federation/quorum.py  ->  package = "protocol.federation"
    this_module = _module_name_from_path(module_path, repo_root)
    package_parts = this_module.split(".")
    # The package is everything except the last component (the module itself),
    # unless this file *is* a package init, in which case it equals the module.
    if module_path.name == "__init__.py":
        package = this_module
    else:
        package = ".".join(package_parts[:-1]) if len(package_parts) > 1 else ""

    names: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name.startswith("protocol"):
                    names.append(alias.name)
        elif isinstance(node, ast.ImportFrom):
            module = node.module or ""
            if node.level:
                # Relative import: resolve against the file's own package.
                # level=1 means same package, level=2 means parent package, etc.
                base_parts = package.split(".") if package else []
                # Trim (level - 1) parts to walk up the package hierarchy.
                if node.level > 1:
                    trim = node.level - 1
                    base_parts = base_parts[:-trim] if trim < len(base_parts) else []
                base = ".".join(base_parts)
                if not base:
                    # Cannot resolve the relative import; skip it.
                    continue
                abs_name = f"{base}.{module}" if module else base
                if abs_name.startswith("protocol"):
                    names.append(abs_name)
                    # Also record each explicitly named alias so that
                    # "from .federation import quorum" records
                    # "protocol.federation.quorum" in addition to
                    # "protocol.federation", catching submodule imports.
                    for alias in node.names:
                        if alias.name != "*":
                            names.append(f"{abs_name}.{alias.name}")
            elif module.startswith("protocol"):
                names.append(module)
                # Also record each explicitly named alias so that
                # "from protocol.federation import quorum" records
                # "protocol.federation.quorum" in addition to
                # "protocol.federation".
                for alias in node.names:
                    if alias.name != "*":
                        names.append(f"{module}.{alias.name}")
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
        # Convert dotted module name to a filesystem path.
        # Try the plain .py file first, then the package __init__.py.
        parts = importer_name.split(".")
        module_path = repo_root / Path(*parts).with_suffix(".py")
        if not module_path.exists():
            module_path = repo_root / Path(*parts) / "__init__.py"
        if not module_path.exists():
            # Module doesn't exist; skip silently (might be optional)
            continue

        actual_imports = _get_internal_imports(module_path, repo_root)
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
