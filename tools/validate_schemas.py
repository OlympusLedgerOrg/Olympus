#!/usr/bin/env python3
"""
Validate JSON Schema files under ./schemas.

Goals:
- Ensure schemas are valid JSON.
- Ensure schemas are valid JSON Schema documents (best-effort).
- Enforce basic audit hygiene: unique $id and resolvable local $ref.
"""

from __future__ import annotations

import json
import sys
from collections.abc import Iterable
from pathlib import Path
from typing import Any

SCHEMAS_DIR = Path(__file__).resolve().parents[1] / "schemas"


def load_json(path: Path) -> dict[str, Any]:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception as e:
        raise ValueError(f"{path}: invalid JSON: {e}") from e


def iter_schema_files() -> Iterable[Path]:
    if not SCHEMAS_DIR.exists():
        raise ValueError(f"schemas dir not found: {SCHEMAS_DIR}")
    yield from sorted(SCHEMAS_DIR.glob("*.json"))


def collect_ids(schemas: dict[Path, dict[str, Any]]) -> tuple[set[str], list[str]]:
    seen: set[str] = set()
    errors: list[str] = []
    for path, doc in schemas.items():
        sid = doc.get("$id")
        if not sid:
            # Not fatal, but highly recommended for auditability.
            errors.append(f"{path.name}: missing $id (recommended to set a stable $id)")
            continue
        if sid in seen:
            errors.append(f"{path.name}: duplicate $id: {sid}")
        seen.add(sid)
    return seen, errors


def walk_refs(obj: Any, out: set[str]) -> None:
    if isinstance(obj, dict):
        if "$ref" in obj and isinstance(obj["$ref"], str):
            out.add(obj["$ref"])
        for v in obj.values():
            walk_refs(v, out)
    elif isinstance(obj, list):
        for v in obj:
            walk_refs(v, out)


def check_local_refs(
    schemas: dict[Path, dict[str, Any]],
) -> list[str]:
    """
    Best-effort local ref validation.

    We consider local refs of the form:
    - "leaf_record.json#/$defs/Thing"
    - "canonical_document.json#/properties/x"

    We do not try to resolve remote URLs here.
    """
    available_files = {p.name for p in schemas}
    errors: list[str] = []

    for path, doc in schemas.items():
        refs: set[str] = set()
        walk_refs(doc, refs)
        for ref in sorted(refs):
            if "://" in ref:
                # Remote refs allowed; not validated here.
                continue
            if ref.startswith("#"):
                # Internal ref within same schema; assume OK (jsonschema will catch many issues)
                continue
            # file ref
            target_file = ref.split("#", 1)[0]
            if target_file and target_file not in available_files:
                errors.append(f"{path.name}: $ref points to missing schema file: {ref}")
    return errors


def validate_with_jsonschema(schemas: dict[Path, dict[str, Any]]) -> list[str]:
    """
    Validate each schema document as a JSON Schema.
    Uses jsonschema if installed.
    """
    errors: list[str] = []
    try:
        from jsonschema.validators import validator_for  # type: ignore[import-untyped]
    except Exception:
        return ["jsonschema not installed; cannot validate JSON Schema documents"]

    for path, doc in schemas.items():
        try:
            validator = validator_for(doc)
            validator.check_schema(doc)
        except Exception as e:
            errors.append(f"{path.name}: invalid JSON Schema: {e}")
    return errors


def main() -> int:
    schema_files = list(iter_schema_files())
    if not schema_files:
        print("No schema files found under schemas/*.json", file=sys.stderr)
        return 2

    schemas: dict[Path, dict[str, Any]] = {}
    errors: list[str] = []

    # Load JSON
    for p in schema_files:
        try:
            schemas[p] = load_json(p)
        except ValueError as e:
            errors.append(str(e))

    if errors:
        for e in errors:
            print(e, file=sys.stderr)
        return 1

    # Hygiene checks
    _, id_errors = collect_ids(schemas)
    ref_errors = check_local_refs(schemas)
    schema_errors = validate_with_jsonschema(schemas)

    # Treat duplicate $id / broken local $ref / invalid schema as failures
    hard_fail: list[str] = []
    soft_warn: list[str] = []

    for e in id_errors:
        # missing $id => warn; duplicate => fail
        if "duplicate $id" in e:
            hard_fail.append(e)
        else:
            soft_warn.append(e)

    for e in ref_errors:
        hard_fail.append(e)

    for e in schema_errors:
        # missing jsonschema dependency should fail CI: you want deterministic protocol checks
        hard_fail.append(e)

    for w in soft_warn:
        print(f"WARNING: {w}", file=sys.stderr)

    if hard_fail:
        for e in hard_fail:
            print(f"ERROR: {e}", file=sys.stderr)
        return 1

    print(f"OK: validated {len(schemas)} schema file(s)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
