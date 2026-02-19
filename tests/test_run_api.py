import os
import subprocess
import sys
from pathlib import Path


REPO_ROOT = Path(__file__).parent.parent
RUN_API_PATH = REPO_ROOT / "run_api.py"


def test_run_api_exits_when_database_url_missing():
    env = os.environ.copy()
    env.pop("DATABASE_URL", None)

    result = subprocess.run(
        [sys.executable, str(RUN_API_PATH)],
        capture_output=True,
        text=True,
        env=env,
        cwd=REPO_ROOT,
    )

    assert result.returncode == 2
    assert "DATABASE_URL is required" in result.stderr


def test_api_app_import_works_without_database_url():
    env = os.environ.copy()
    env.pop("DATABASE_URL", None)

    result = subprocess.run(
        [sys.executable, "-c", "import api.app"],
        capture_output=True,
        text=True,
        env=env,
        cwd=REPO_ROOT,
    )

    assert result.returncode == 0
