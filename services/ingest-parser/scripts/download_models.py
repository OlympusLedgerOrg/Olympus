#!/usr/bin/env python3
"""
Model Download and Hash Script for Ingest Parser Service.

This script downloads AI model weights at build time, computes their
SHA256 hash, and generates a configuration file with the pinned hash.

Usage:
    python scripts/download_models.py --backend docling --output /models

The script outputs a JSON file with model metadata:
{
    "model_name": "docling",
    "model_version": "2.1.0",
    "model_hash": "sha256_abc123...",
    "download_timestamp": "2024-01-01T00:00:00Z",
    "files": [
        {"path": "model.bin", "hash": "sha256_...", "size": 12345}
    ]
}
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path


def compute_sha256(file_path: Path) -> str:
    """Compute SHA256 hash of a file."""
    hasher = hashlib.sha256()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            hasher.update(chunk)
    return f"sha256_{hasher.hexdigest()}"


def compute_directory_hash(dir_path: Path) -> str:
    """Compute SHA256 hash of a directory's contents."""
    hasher = hashlib.sha256()
    files = sorted(dir_path.rglob("*"))

    for file_path in files:
        if file_path.is_file():
            rel_path = file_path.relative_to(dir_path)
            hasher.update(str(rel_path).encode("utf-8"))
            hasher.update(b"\x00")
            with open(file_path, "rb") as f:
                for chunk in iter(lambda: f.read(65536), b""):
                    hasher.update(chunk)

    return f"sha256_{hasher.hexdigest()}"


def download_docling_models(output_dir: Path) -> dict:
    """Download Docling models and return metadata."""
    try:
        from importlib.metadata import version

        from docling.document_converter import DocumentConverter

        # Initialize converter to trigger model download as a side effect
        print("Initializing Docling (this may download models)...")
        DocumentConverter()  # Side effect: downloads models to cache

        docling_version = version("docling")

        # Compute hash of the model cache directory
        # Docling typically caches models in ~/.cache/docling or similar
        import os
        cache_dir = Path(os.path.expanduser("~/.cache/docling"))

        if cache_dir.exists():
            model_hash = compute_directory_hash(cache_dir)

            # List all model files
            files = []
            for file_path in sorted(cache_dir.rglob("*")):
                if file_path.is_file():
                    files.append({
                        "path": str(file_path.relative_to(cache_dir)),
                        "hash": compute_sha256(file_path),
                        "size": file_path.stat().st_size,
                    })
        else:
            model_hash = "sha256_" + "0" * 64
            files = []

        return {
            "model_name": "docling",
            "model_version": docling_version,
            "model_hash": model_hash,
            "download_timestamp": datetime.now(timezone.utc).isoformat(),
            "files": files,
        }

    except ImportError:
        print("ERROR: Docling is not installed", file=sys.stderr)
        sys.exit(1)


def download_marker_models(output_dir: Path) -> dict:
    """Download Marker models and return metadata."""
    try:
        from importlib.metadata import version

        marker_version = version("marker-pdf")

        # Marker also caches models
        import os
        cache_dir = Path(os.path.expanduser("~/.cache/marker"))

        if cache_dir.exists():
            model_hash = compute_directory_hash(cache_dir)
            files = []
            for file_path in sorted(cache_dir.rglob("*")):
                if file_path.is_file():
                    files.append({
                        "path": str(file_path.relative_to(cache_dir)),
                        "hash": compute_sha256(file_path),
                        "size": file_path.stat().st_size,
                    })
        else:
            model_hash = "sha256_" + "0" * 64
            files = []

        return {
            "model_name": "marker",
            "model_version": marker_version,
            "model_hash": model_hash,
            "download_timestamp": datetime.now(timezone.utc).isoformat(),
            "files": files,
        }

    except ImportError:
        print("ERROR: Marker is not installed", file=sys.stderr)
        sys.exit(1)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Download and hash AI models for the ingest-parser service"
    )
    parser.add_argument(
        "--backend",
        choices=["docling", "marker", "fallback"],
        default="fallback",
        help="Parser backend to download models for",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("/models"),
        help="Output directory for model metadata",
    )

    args = parser.parse_args()

    # Create output directory
    args.output.mkdir(parents=True, exist_ok=True)

    # Download models based on backend
    if args.backend == "docling":
        metadata = download_docling_models(args.output)
    elif args.backend == "marker":
        metadata = download_marker_models(args.output)
    else:
        # Fallback has no models
        metadata = {
            "model_name": "fallback",
            "model_version": "1.0.0",
            "model_hash": "sha256_" + "0" * 64,
            "download_timestamp": datetime.now(timezone.utc).isoformat(),
            "files": [],
        }

    # Write metadata
    metadata_path = args.output / "model_metadata.json"
    with open(metadata_path, "w") as f:
        json.dump(metadata, f, indent=2)

    print(f"Model metadata written to: {metadata_path}")
    print(f"Model hash: {metadata['model_hash']}")

    # Also print for use in Docker build
    print("\nFor Dockerfile ARG:")
    print(f"  INGEST_PARSER_MODEL_HASH={metadata['model_hash']}")


if __name__ == "__main__":
    main()
