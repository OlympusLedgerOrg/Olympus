"""
Backward-compatibility shim.

This module re-exports the unified app and storage helpers so that
existing tests and tooling that import from ``api.app`` continue to work.

New code should import from ``api.main`` directly.
"""

from api.main import app  # noqa: F401
from api.services.storage_layer import (  # noqa: F401
    _get_storage,
    _require_storage,
)


__all__ = ["app", "_get_storage", "_require_storage"]
