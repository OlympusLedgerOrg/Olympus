"""Tests that storage modules raise RuntimeError when olympus_core is absent."""

from __future__ import annotations

import os
import sys
import unittest


class TestRustRequired(unittest.TestCase):
    """olympus_core must be present for storage modules when OLYMPUS_REQUIRE_RUST=1."""

    def test_storage_postgres_raises_without_olympus_core_when_required(self) -> None:
        """storage.postgres raises RuntimeError at import when olympus_core is absent and required."""
        # Save the original olympus_core module
        orig_olympus_core = sys.modules.get("olympus_core")
        orig_require_rust = os.environ.get("OLYMPUS_REQUIRE_RUST")

        # Remove olympus_core from sys.modules and prevent reimport
        if "olympus_core" in sys.modules:
            del sys.modules["olympus_core"]

        # Also remove storage.postgres so it can be reimported
        orig_storage_postgres = sys.modules.pop("storage.postgres", None)
        orig_storage = sys.modules.pop("storage", None)

        import builtins

        real_import = builtins.__import__

        def _fake_import(name: str, *args, **kwargs):
            if name == "olympus_core" or name.startswith("olympus_core."):
                raise ImportError("No module named 'olympus_core'")
            return real_import(name, *args, **kwargs)

        try:
            # Set OLYMPUS_REQUIRE_RUST=1 to trigger the error
            os.environ["OLYMPUS_REQUIRE_RUST"] = "1"

            # Patch builtins.__import__ to block olympus_core
            builtins.__import__ = _fake_import

            with self.assertRaises(RuntimeError) as ctx:
                import storage.postgres  # noqa: F401

            self.assertIn("OLYMPUS_REQUIRE_RUST=1", str(ctx.exception))

        finally:
            # Restore original __import__
            builtins.__import__ = real_import

            # Restore environment
            if orig_require_rust is not None:
                os.environ["OLYMPUS_REQUIRE_RUST"] = orig_require_rust
            else:
                os.environ.pop("OLYMPUS_REQUIRE_RUST", None)

            # Restore sys.modules
            if orig_olympus_core is not None:
                sys.modules["olympus_core"] = orig_olympus_core
            if orig_storage_postgres is not None:
                sys.modules["storage.postgres"] = orig_storage_postgres
            if orig_storage is not None:
                sys.modules["storage"] = orig_storage

    def test_storage_protocol_state_raises_without_olympus_core_when_required(self) -> None:
        """storage.protocol_state raises RuntimeError at import when olympus_core is absent and required."""
        # Save the original olympus_core module
        orig_olympus_core = sys.modules.get("olympus_core")
        orig_require_rust = os.environ.get("OLYMPUS_REQUIRE_RUST")

        # Remove olympus_core from sys.modules and prevent reimport
        if "olympus_core" in sys.modules:
            del sys.modules["olympus_core"]

        # Also remove storage.protocol_state so it can be reimported
        orig_storage_protocol_state = sys.modules.pop("storage.protocol_state", None)

        import builtins

        real_import = builtins.__import__

        def _fake_import(name: str, *args, **kwargs):
            if name == "olympus_core" or name.startswith("olympus_core."):
                raise ImportError("No module named 'olympus_core'")
            return real_import(name, *args, **kwargs)

        try:
            # Set OLYMPUS_REQUIRE_RUST=1 to trigger the error
            os.environ["OLYMPUS_REQUIRE_RUST"] = "1"

            # Patch builtins.__import__ to block olympus_core
            builtins.__import__ = _fake_import

            with self.assertRaises(RuntimeError) as ctx:
                import storage.protocol_state  # noqa: F401

            self.assertIn("OLYMPUS_REQUIRE_RUST=1", str(ctx.exception))

        finally:
            # Restore original __import__
            builtins.__import__ = real_import

            # Restore environment
            if orig_require_rust is not None:
                os.environ["OLYMPUS_REQUIRE_RUST"] = orig_require_rust
            else:
                os.environ.pop("OLYMPUS_REQUIRE_RUST", None)

            # Restore sys.modules
            if orig_olympus_core is not None:
                sys.modules["olympus_core"] = orig_olympus_core
            if orig_storage_protocol_state is not None:
                sys.modules["storage.protocol_state"] = orig_storage_protocol_state


if __name__ == "__main__":
    unittest.main()
