#!/usr/bin/env python3
"""Benchmark canonicalization throughput with optional multiprocessing."""

from __future__ import annotations

import argparse
import io
import json
import time
from pathlib import Path

import pikepdf

from protocol.canonicalizer import ArtifactPayload, process_artifacts_concurrently


RESULTS_DIR = Path(__file__).resolve().parent / "results"


def _build_pdf() -> bytes:
    pdf = pikepdf.Pdf.new()
    pdf.add_blank_page(page_size=(612, 792))
    buf = io.BytesIO()
    pdf.save(buf)
    return buf.getvalue()


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Benchmark Olympus canonicalizer performance.")
    parser.add_argument(
        "--copies",
        type=int,
        default=4,
        help="Number of PDF artifacts to process.",
    )
    parser.add_argument(
        "--workers",
        type=int,
        default=2,
        help="Number of worker processes for multiprocessing.",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=RESULTS_DIR / "canonicalization_benchmark.json",
        help="Output JSON file for benchmark results.",
    )
    return parser.parse_args()


def main() -> None:
    args = _parse_args()
    sample_pdf = _build_pdf()
    payloads = [
        ArtifactPayload(raw_data=sample_pdf, mime_type="application/pdf")
        for _ in range(args.copies)
    ]

    start = time.perf_counter()
    process_artifacts_concurrently(payloads, max_workers=args.workers)
    elapsed = time.perf_counter() - start

    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    results = {
        "copies": args.copies,
        "workers": args.workers,
        "total_seconds": elapsed,
        "seconds_per_copy": elapsed / max(args.copies, 1),
    }
    args.output.write_text(json.dumps(results, indent=2), encoding="utf-8")
    print(f"Wrote canonicalization benchmark results to {args.output}")


if __name__ == "__main__":
    main()
