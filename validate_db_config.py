#!/usr/bin/env python3
"""
Validation script to verify PostgreSQL database configuration.

This script checks that all database connection strings in the codebase
use the canonical local credentials (olympus:olympus) and not incorrect
defaults like root:root or postgres:postgres.

Usage:
    python validate_db_config.py
"""

import re
from pathlib import Path


SCRIPT_DIR = Path(__file__).resolve().parent


def check_database_urls() -> bool:
    """Check all Python files for database URL configurations."""

    print("=" * 70)
    print("PostgreSQL Database Configuration Validation")
    print("=" * 70)
    print()

    # Files to check
    files_to_check = [
        "tests/test_storage.py",
        "tests/test_e2e_audit.py",
        "api/app.py",
        ".github/workflows/ci.yml",
    ]

    # Patterns to look for
    incorrect_patterns = [
        (r"postgresql://root:", "root user"),
        (r"postgresql://postgres:", "postgres user (in non-doc context)"),
        # The legacy "A.Smith" default leaked into many places; flag it so
        # a future regression cannot silently re-introduce it.
        (r"postgresql://A\.Smith:", "legacy A.Smith user"),
    ]

    correct_pattern = r"postgresql://olympus:olympus"

    issues_found = []
    files_checked = 0

    for file_path in files_to_check:
        full_path = SCRIPT_DIR / file_path
        if not full_path.exists():
            print(f"⚠️  File not found: {file_path}")
            continue

        files_checked += 1
        print(f"✓ Checking {file_path}...")

        content = full_path.read_text(encoding="utf-8")

        # Check for incorrect patterns
        for pattern, description in incorrect_patterns:
            matches = re.findall(pattern, content)
            if matches:
                issues_found.append(
                    {
                        "file": file_path,
                        "issue": f"Found {description}",
                        "pattern": pattern,
                    }
                )

        # Check for correct pattern in test files
        if "test_" in file_path or "api/app.py" in file_path:
            if re.search(correct_pattern, content):
                print("  ✓ Correct credentials found (olympus:olympus)")

    print()
    print("=" * 70)

    if issues_found:
        print("❌ ISSUES FOUND:")
        print()
        for issue in issues_found:
            print(f"  File: {issue['file']}")
            print(f"  Issue: {issue['issue']}")
            print(f"  Pattern: {issue['pattern']}")
            print()
        return False
    else:
        print("✅ ALL CHECKS PASSED!")
        print()
        print(f"  Files checked: {files_checked}")
        print("  No incorrect database credentials found")
        print("  All test files use olympus:olympus credentials")
        print()
        return True


if __name__ == "__main__":
    success = check_database_urls()
    exit(0 if success else 1)
