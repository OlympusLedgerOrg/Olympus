"""
Artifact persistence for reproducible fuzzing failures.

When a fuzz test discovers a failing case it calls ``save_artifact()`` to
write a JSON file under ``.hypothesis/fuzz-artifacts/``.  The artifact
contains enough information to reproduce the failure:

* ``seed``                — Hypothesis seed (``--hypothesis-seed=N``)
* ``profile``             — active Hypothesis profile
* ``timestamp``           — ISO 8601 UTC
* ``operations``          — list of operation descriptors up to ``failing_index``
* ``failing_index``       — zero-based index of the failing operation
* ``failing_operation``   — copy of the failing operation descriptor
* ``expected``            — expected root hash / invariant value (hex or str)
* ``actual``              — actual value observed (hex or str)
* ``exception``           — ``repr(exc)`` or ``None``
* ``replay_command``      — pytest command to replay the failure
* ``endpoint``            — endpoint or function name (for API/security tests)
* ``expected_status``     — expected HTTP status code (for API tests)
* ``actual_status``       — actual HTTP status code (for API tests)
* ``sanitized_body``      — response body with secrets redacted

Artifacts are sanitized before writing to ensure no secrets, signing keys,
database URLs, or environment values are embedded.
"""

from __future__ import annotations

import json
import os
import re
import traceback
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


_REPO_ROOT = Path(__file__).resolve().parent.parent.parent
_ARTIFACT_DIR = _REPO_ROOT / ".hypothesis" / "fuzz-artifacts"


# ---------------------------------------------------------------------------
# Sanitization — strip values that look like secrets
# ---------------------------------------------------------------------------

# Patterns that might indicate a secret or internal value in an artifact
_SECRET_PATTERNS = [
    re.compile(r"(?i)password\s*[=:]\s*\S+"),
    re.compile(r"(?i)secret\s*[=:]\s*\S+"),
    re.compile(r"(?i)api[_-]?key\s*[=:]\s*\S+"),
    re.compile(r"(?i)signing[_-]?key\s*[=:]\s*\S+"),
    re.compile(r"(?i)database[_-]?url\s*[=:]\s*\S+"),
    re.compile(r"postgresql://[^\"'\s]+"),
    re.compile(r"sqlite:///[^\"'\s]+"),
    # Ed25519 private key material (base64-like 64+ chars)
    re.compile(r"[A-Za-z0-9+/]{64,}={0,2}"),
]


def _sanitize_string(value: str) -> str:
    """Replace potentially sensitive patterns with a placeholder."""
    for pat in _SECRET_PATTERNS:
        value = pat.sub("[REDACTED]", value)
    return value


def _sanitize_value(value: Any, depth: int = 0) -> Any:
    """Recursively sanitize a JSON-serializable value."""
    if depth > 8:
        return "[truncated]"
    if isinstance(value, str):
        return _sanitize_string(value)
    if isinstance(value, dict):
        return {k: _sanitize_value(v, depth + 1) for k, v in value.items()}
    if isinstance(value, list):
        return [_sanitize_value(v, depth + 1) for v in value]
    return value


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def save_artifact(
    *,
    test_name: str,
    operations: list[dict[str, Any]],
    failing_index: int,
    failing_operation: dict[str, Any] | None = None,
    expected: Any = None,
    actual: Any = None,
    exception: BaseException | None = None,
    seed: int | None = None,
    profile: str | None = None,
    # API / security test extras
    endpoint: str | None = None,
    expected_status: int | None = None,
    actual_status: int | None = None,
    sanitized_body: Any = None,
) -> Path:
    """
    Save a reproducible failure artifact as a JSON file.

    Args:
        test_name: Name of the test function that failed.
        operations: Full list of operation descriptors executed so far.
        failing_index: Zero-based index of the first failing operation.
        failing_operation: Copy of the failing operation (defaults to
            ``operations[failing_index]`` when present).
        expected: Expected value (root hash hex, invariant, status code …).
        actual: Actual value observed.
        exception: Exception instance (if any).
        seed: Hypothesis seed integer.
        profile: Active Hypothesis profile name.
        endpoint: API endpoint or function name (for security tests).
        expected_status: Expected HTTP status code.
        actual_status: Actual HTTP status code returned.
        sanitized_body: Response body with secrets already redacted.

    Returns:
        Path to the saved artifact file.
    """
    _ARTIFACT_DIR.mkdir(parents=True, exist_ok=True)

    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    safe_name = re.sub(r"[^a-zA-Z0-9_\-]", "_", test_name)
    artifact_path = _ARTIFACT_DIR / f"{safe_name}_{ts}.json"

    if failing_operation is None and 0 <= failing_index < len(operations):
        failing_operation = operations[failing_index]

    active_profile = profile or os.environ.get("HYPOTHESIS_PROFILE", "fuzz_smoke")

    # Build replay command
    replay_cmd_parts = [
        "pytest",
        f"tests/fuzz/{_guess_module(test_name)}",
        f"-k '{test_name}'",
        "--tb=short",
        "-v",
    ]
    if seed is not None:
        replay_cmd_parts.append(f"--hypothesis-seed={seed}")
    replay_cmd = " ".join(replay_cmd_parts)

    exc_text: str | None = None
    if exception is not None:
        # Only keep the exception type + message + minimal traceback (no paths)
        exc_text = _sanitize_string(
            "".join(traceback.format_exception(type(exception), exception, exception.__traceback__))
        )

    artifact: dict[str, Any] = {
        "test_name": test_name,
        "seed": seed,
        "profile": active_profile,
        "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "operations": _sanitize_value(operations[: failing_index + 1]),
        "failing_index": failing_index,
        "failing_operation": _sanitize_value(failing_operation),
        "expected": _sanitize_value(expected),
        "actual": _sanitize_value(actual),
        "exception": exc_text,
        "replay_command": replay_cmd,
    }

    if endpoint is not None:
        artifact["endpoint"] = endpoint
    if expected_status is not None:
        artifact["expected_status"] = expected_status
    if actual_status is not None:
        artifact["actual_status"] = actual_status
    if sanitized_body is not None:
        artifact["sanitized_body"] = _sanitize_value(sanitized_body)

    with open(artifact_path, "w", encoding="utf-8") as fh:
        json.dump(artifact, fh, indent=2, default=str)

    return artifact_path


def _guess_module(test_name: str) -> str:
    """Guess the test module filename from a test function name."""
    if "security" in test_name:
        return "test_security_invariants_fuzz.py"
    return "test_storage_invariants_fuzz.py"
