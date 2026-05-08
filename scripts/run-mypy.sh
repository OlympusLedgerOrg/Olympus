#!/bin/sh
# Run mypy from the project virtual environment so all installed type stubs
# and third-party packages are visible.  pre-commit's mirrors-mypy hook runs
# in an isolated sandbox and misses deps; this script avoids that problem.
#
# Works on Linux/macOS (.venv/bin/mypy) and Windows Git-Bash / WSL
# (.venv/Scripts/mypy or .venv/Scripts/mypy.exe).
set -e
if   [ -x ".venv/bin/mypy" ];         then exec ".venv/bin/mypy" "$@"
elif [ -x ".venv/Scripts/mypy" ];     then exec ".venv/Scripts/mypy" "$@"
elif [ -x ".venv/Scripts/mypy.exe" ]; then exec ".venv/Scripts/mypy.exe" "$@"
else
    echo "ERROR: mypy not found in .venv — activate the virtualenv first" >&2
    exit 1
fi
