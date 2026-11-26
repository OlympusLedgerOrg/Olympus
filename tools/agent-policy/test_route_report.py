#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Olympus Contributors
# SPDX-License-Identifier: Apache-2.0

"""Tests for route_report.py: malformed lines and the tier/token totals.

Run directly (no pytest, no package install):

    python tools/agent-policy/test_route_report.py

Loaded by path rather than as a module because `tools/agent-policy` is not an
importable package name (the hyphen), and adding an `__init__.py` to make it one
would exist only for this test.
"""

from __future__ import annotations

import io
import importlib.util
import json
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

HERE = Path(__file__).resolve().parent
_spec = importlib.util.spec_from_file_location("route_report", HERE / "route_report.py")
route_report = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(route_report)


def write_log(lines: list[str]) -> Path:
    handle = tempfile.NamedTemporaryFile("w", suffix=".jsonl", delete=False, encoding="utf-8")
    handle.write("\n".join(lines) + "\n")
    handle.close()
    return Path(handle.name)


def route(tier: str, **overrides) -> str:
    record = {
        "kind": "route",
        "tier": tier,
        "task": "t",
        "escalated": False,
        "deniedPaths": [],
    }
    record.update(overrides)
    return json.dumps(record)


def usage(model: str, prompt: int, completion: int, duration: int) -> str:
    return json.dumps(
        {
            "kind": "usage",
            "model": model,
            "promptTokens": prompt,
            "completionTokens": completion,
            "durationMs": duration,
        }
    )


class ReadRecordsTest(unittest.TestCase):
    def test_malformed_lines_are_counted_and_skipped(self):
        path = write_log(
            [
                route("local"),
                "not json at all",
                "",
                json.dumps([1, 2]),  # valid JSON, wrong shape
                usage("qwen", 10, 2, 5),
            ]
        )
        records, malformed = route_report.read_records(path)
        self.assertEqual(malformed, 2)
        self.assertEqual(len(records), 2)
        self.assertEqual([entry["kind"] for entry in records], ["route", "usage"])


class SummariseTest(unittest.TestCase):
    def test_tier_totals_and_escalations(self):
        records = [
            {"kind": "route", "tier": "local", "escalated": False, "deniedPaths": []},
            {"kind": "route", "tier": "local", "escalated": True, "deniedPaths": ["src-tauri/x"]},
            {"kind": "route", "tier": "top", "escalated": True, "deniedPaths": []},
            {"kind": "route", "tier": "deterministic", "escalated": False},
        ]
        summary = route_report.summarise(records)
        self.assertEqual(summary["routes"], 4)
        self.assertEqual(
            summary["tiers"],
            {"deterministic": 1, "local": 2, "mid": 0, "top": 1},
        )
        self.assertEqual(summary["escalated"], 2)
        self.assertEqual(summary["withDeniedPaths"], 1)

    def test_token_totals_and_slowest_across_models(self):
        records = [
            {"kind": "usage", "model": "qwen-a", "promptTokens": 900, "completionTokens": 30, "durationMs": 1200},
            {"kind": "usage", "model": "qwen-a", "promptTokens": 100, "completionTokens": 20, "durationMs": 9000},
            {"kind": "usage", "model": "qwen-b", "promptTokens": 50, "completionTokens": 5, "durationMs": 300},
        ]
        summary = route_report.summarise(records)
        self.assertEqual(summary["usageCalls"], 3)
        self.assertEqual(summary["promptTokens"], 1050)
        self.assertEqual(summary["completionTokens"], 55)
        self.assertEqual(summary["slowestMs"], 9000)
        self.assertEqual(
            summary["byModel"]["qwen-a"],
            {"calls": 2, "promptTokens": 1000, "completionTokens": 50},
        )
        self.assertEqual(summary["byModel"]["qwen-b"]["calls"], 1)

    def test_missing_token_fields_count_as_zero_not_an_error(self):
        summary = route_report.summarise(
            [{"kind": "usage", "model": "qwen", "promptTokens": None, "durationMs": None}]
        )
        self.assertEqual(summary["promptTokens"], 0)
        self.assertEqual(summary["completionTokens"], 0)
        self.assertEqual(summary["slowestMs"], 0)

    def test_report_names_malformed_count_only_when_present(self):
        clean = route_report.format_report(route_report.summarise([]), 0)
        self.assertNotIn("malformed", clean)
        dirty = route_report.format_report(route_report.summarise([]), 3)
        self.assertIn("3 malformed (skipped)", dirty)


class MainTest(unittest.TestCase):
    def test_missing_log_exits_1_with_a_reason(self):
        stderr = io.StringIO()
        with redirect_stderr(stderr), redirect_stdout(io.StringIO()):
            code = route_report.main([str(HERE / "does-not-exist.jsonl")])
        self.assertEqual(code, 1)
        self.assertIn("no log at", stderr.getvalue())

    def test_json_output_carries_the_totals(self):
        path = write_log([route("local"), usage("qwen", 84, 2, 196)])
        stdout = io.StringIO()
        with redirect_stdout(stdout):
            code = route_report.main([str(path), "--json"])
        self.assertEqual(code, 0)
        payload = json.loads(stdout.getvalue())
        self.assertEqual(payload["tiers"], {"deterministic": 0, "local": 1, "mid": 0, "top": 0})
        self.assertEqual(payload["promptTokens"], 84)
        self.assertEqual(payload["completionTokens"], 2)


if __name__ == "__main__":
    unittest.main(verbosity=2)
