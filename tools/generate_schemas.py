"""
Schema alignment automation for Olympus.

Generates JSON Schema definitions from Pydantic models so that the canonical
``schemas/`` directory stays in sync with the Python source of truth.

Usage::

    python -m tools.generate_schemas          # writes to schemas/generated/
    python -m tools.generate_schemas --check  # exits non-zero on drift

This eliminates manual schema maintenance and reduces drift between the API
models and the JSON schemas consumed by external integrators.
"""

from __future__ import annotations

import importlib
import json
import sys
from pathlib import Path
from typing import Any

from pydantic import BaseModel


# ---------------------------------------------------------------------------
# Registry of models to export
# ---------------------------------------------------------------------------

_MODEL_REGISTRY: list[tuple[str, str, str]] = [
    # (module_path, class_name, output_filename)
    ("api.ingest", "RecordInput", "record_input.json"),
    ("api.ingest", "BatchIngestionRequest", "batch_ingestion_request.json"),
]


def discover_models() -> list[tuple[str, type[BaseModel]]]:
    """
    Import and return all registered Pydantic models.

    Returns:
        List of (output_filename, model_class) tuples.
    """
    results: list[tuple[str, type[BaseModel]]] = []
    for module_path, class_name, filename in _MODEL_REGISTRY:
        try:
            mod = importlib.import_module(module_path)
            cls = getattr(mod, class_name)
            if isinstance(cls, type) and issubclass(cls, BaseModel):
                results.append((filename, cls))
        except Exception as exc:
            # Modules like api.ingest may not be importable outside the
            # API context (missing env vars, database, etc.).  Log and skip.
            import logging

            logging.getLogger(__name__).debug(
                "Skipping %s.%s: %s", module_path, class_name, exc
            )
    return results


def generate_json_schema(model_cls: type[BaseModel]) -> dict[str, Any]:
    """
    Generate a JSON Schema from a Pydantic model.

    Args:
        model_cls: Pydantic BaseModel subclass.

    Returns:
        JSON Schema dictionary.
    """
    return model_cls.model_json_schema()


def write_schemas(output_dir: str | Path) -> list[str]:
    """
    Write generated schemas to the output directory.

    Args:
        output_dir: Directory to write schema files.

    Returns:
        List of written file paths.
    """
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)

    written: list[str] = []
    for filename, model_cls in discover_models():
        schema = generate_json_schema(model_cls)
        filepath = output_path / filename
        filepath.write_text(
            json.dumps(schema, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        written.append(str(filepath))

    return written


def check_schemas(output_dir: str | Path) -> list[str]:
    """
    Check whether generated schemas match the files on disk.

    Args:
        output_dir: Directory containing existing schema files.

    Returns:
        List of filenames that are out of date.
    """
    output_path = Path(output_dir)
    drifted: list[str] = []

    for filename, model_cls in discover_models():
        schema = generate_json_schema(model_cls)
        expected = json.dumps(schema, indent=2, sort_keys=True) + "\n"

        filepath = output_path / filename
        if not filepath.exists():
            drifted.append(filename)
            continue

        actual = filepath.read_text(encoding="utf-8")
        if actual != expected:
            drifted.append(filename)

    return drifted


def main() -> None:
    """CLI entry point for schema generation."""
    repo_root = Path(__file__).resolve().parent.parent
    output_dir = repo_root / "schemas" / "generated"

    if "--check" in sys.argv:
        drifted = check_schemas(output_dir)
        if drifted:
            print(f"Schema drift detected in: {', '.join(drifted)}", file=sys.stderr)
            sys.exit(1)
        else:
            print("All schemas are up to date.")
            sys.exit(0)
    else:
        written = write_schemas(output_dir)
        for path in written:
            print(f"  wrote {path}")
        print(f"Generated {len(written)} schema(s).")


if __name__ == "__main__":
    main()
