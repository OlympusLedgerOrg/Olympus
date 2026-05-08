#!/usr/bin/env python3
"""
Run mypy from the project virtual environment.

pre-commit's mirrors-mypy hook runs in an isolated sandbox without access
to the project's installed packages and type stubs.  This script finds the
venv-local mypy so all stubs are visible — works on Linux, macOS, and Windows
without requiring the venv to be activated first.
"""

import os
import subprocess
import sys


_VENV_ROOT = os.path.join(os.path.dirname(__file__), "..", ".venv")

_CANDIDATES = [
    os.path.join(_VENV_ROOT, "bin", "mypy"),  # Linux / macOS
    os.path.join(_VENV_ROOT, "Scripts", "mypy"),  # Windows (no .exe)
    os.path.join(_VENV_ROOT, "Scripts", "mypy.exe"),  # Windows (with .exe)
]

mypy_exe = next((p for p in _CANDIDATES if os.path.isfile(p)), None)

if mypy_exe is None:
    print(
        "ERROR: mypy not found in .venv — run: python -m pip install -e '.[dev]'",
        file=sys.stderr,
    )
    sys.exit(1)

result = subprocess.run([mypy_exe] + sys.argv[1:])
sys.exit(result.returncode)
