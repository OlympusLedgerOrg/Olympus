"""
Minimal test that exercises api/app.py (the application factory shim).

Simply importing the module is enough to hit all branches because the file
is a thin re-export.  Real endpoint tests in other modules do the heavy
lifting; this test exists solely to push api/app.py into the coverage scope
now that it has been removed from the coverage omit list.
"""

from __future__ import annotations

import importlib
import os


def test_api_app_importable() -> None:
    """api/app.py can be imported and exposes the 'app' object."""
    os.environ.setdefault("OLYMPUS_ENV", "development")
    mod = importlib.import_module("api.app")
    assert hasattr(mod, "app"), "api.app must export 'app'"
