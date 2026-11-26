#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Olympus Contributors
# SPDX-License-Identifier: Apache-2.0

"""Summarise the route/usage log written by tools/agent-policy/log.mjs.

The log is append-only JSONL. This reads it back and answers the only question
the log exists for: how much work went to each tier, and what did the local tier
spend. A hosted model's billing is not in here — one tier per record is.

Usage:
    python tools/agent-policy/route_report.py [path] [--json]

Exit codes: 0 printed, 1 the log does not exist, 2 usage error.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter, defaultdict
from pathlib import Path

DEFAULT_LOG = Path(__file__).resolve().parents[2] / ".olympus-logs" / "route-report.jsonl"
TIERS = ("deterministic", "local", "mid", "top")


def read_records(path: Path) -> tuple[list[dict], int]:
    """Return the parsed records and the number of lines that were not JSON.

    An append-only log can end in a half-written line after a crash, so a
    malformed line is counted and skipped rather than failing the report.
    """
    records: list[dict] = []
    malformed = 0
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        try:
            parsed = json.loads(line)
        except json.JSONDecodeError:
            malformed += 1
            continue
        if isinstance(parsed, dict):
            records.append(parsed)
        else:
            malformed += 1
    return records, malformed


def summarise(records: list[dict]) -> dict:
    routes = [entry for entry in records if entry.get("kind") == "route"]
    usages = [entry for entry in records if entry.get("kind") == "usage"]

    tier_counts = Counter(entry.get("tier") or "unknown" for entry in routes)
    by_model: dict[str, dict[str, int]] = defaultdict(
        lambda: {"calls": 0, "promptTokens": 0, "completionTokens": 0}
    )
    for entry in usages:
        bucket = by_model[str(entry.get("model") or "unknown")]
        bucket["calls"] += 1
        bucket["promptTokens"] += int(entry.get("promptTokens") or 0)
        bucket["completionTokens"] += int(entry.get("completionTokens") or 0)

    durations = [int(entry.get("durationMs") or 0) for entry in usages]
    return {
        "records": len(records),
        "routes": len(routes),
        "usageCalls": len(usages),
        "tiers": {tier: tier_counts.get(tier, 0) for tier in TIERS}
        | {key: value for key, value in tier_counts.items() if key not in TIERS},
        "escalated": sum(1 for entry in routes if entry.get("escalated")),
        "withDeniedPaths": sum(1 for entry in routes if entry.get("deniedPaths")),
        "promptTokens": sum(bucket["promptTokens"] for bucket in by_model.values()),
        "completionTokens": sum(bucket["completionTokens"] for bucket in by_model.values()),
        "slowestMs": max(durations, default=0),
        "byModel": dict(sorted(by_model.items())),
    }


def format_report(summary: dict, malformed: int) -> str:
    lines = [
        f"records: {summary['records']} valid"
        + (f", {malformed} malformed (skipped)" if malformed else ""),
        "",
        "routing decisions",
    ]
    for tier, count in summary["tiers"].items():
        lines.append(f"  {tier:<14}{count:>4}")
    routes = summary["routes"] or 1
    lines.append(
        f"  escalated      {summary['escalated']:>4}  "
        f"({summary['escalated'] * 100 // routes}%)"
    )
    lines.append(f"  refused paths  {summary['withDeniedPaths']:>4}")
    lines.append("")
    lines.append("local usage (measured, from Ollama)")
    lines.append(f"  calls          {summary['usageCalls']:>4}")
    lines.append(f"  prompt tokens  {summary['promptTokens']:>4}")
    lines.append(f"  output tokens  {summary['completionTokens']:>4}")
    lines.append(f"  slowest        {summary['slowestMs'] / 1000:.1f} s")
    if summary["byModel"]:
        lines.append("")
        lines.append("by model")
        for model, bucket in summary["byModel"].items():
            lines.append(
                f"  {model}: {bucket['calls']} call(s), "
                f"{bucket['promptTokens']} in / {bucket['completionTokens']} out"
            )
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Summarise .olympus-logs/route-report.jsonl")
    parser.add_argument("path", nargs="?", default=str(DEFAULT_LOG), help="JSONL log to read")
    parser.add_argument("--json", action="store_true", help="print the summary as JSON")
    args = parser.parse_args(argv)

    path = Path(args.path)
    if not path.is_file():
        print(f"route-report: no log at {path}", file=sys.stderr)
        print(
            "route-report: it is written by route.mjs and qwen-local ask.mjs; "
            "OLYMPUS_ROUTE_LOG=0 disables it",
            file=sys.stderr,
        )
        return 1

    records, malformed = read_records(path)
    summary = summarise(records)
    if args.json:
        print(json.dumps({"path": str(path), "malformed": malformed, **summary}, indent=2))
    else:
        print(f"route report: {path}")
        print(format_report(summary, malformed))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
