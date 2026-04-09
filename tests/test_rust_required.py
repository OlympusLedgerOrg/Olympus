"""Tests that _append_record_inner raises RuntimeError when olympus_core is absent."""

from __future__ import annotations

import unittest
from unittest.mock import MagicMock, patch

import nacl.signing

from protocol.hashes import global_key, hash_bytes, record_key
from storage.postgres import StorageLayer


def _make_storage() -> StorageLayer:
    """Create a StorageLayer instance without connecting to a real database."""
    with patch.object(StorageLayer, "__init__", lambda self, *a, **kw: None):
        sl = object.__new__(StorageLayer)
        sl._node_cache = {}
        sl._node_cache_maxsize = 4096
        sl._node_cache_lock = MagicMock()
        return sl


class TestRustRequired(unittest.TestCase):
    """olympus_core must be present for _append_record_inner."""

    def test_append_record_inner_raises_without_olympus_core(self) -> None:
        """_append_record_inner raises RuntimeError when olympus_core is not importable."""
        sl = _make_storage()

        # Stub out the connection / cursor context manager
        mock_cur = MagicMock()
        mock_cur.fetchone.return_value = None  # no duplicate
        mock_conn = MagicMock()
        mock_conn.cursor.return_value.__enter__ = MagicMock(return_value=mock_cur)
        mock_conn.cursor.return_value.__exit__ = MagicMock(return_value=False)
        mock_conn.__enter__ = MagicMock(return_value=mock_conn)
        mock_conn.__exit__ = MagicMock(return_value=False)

        sl._get_connection = MagicMock(return_value=mock_conn)
        sl._get_proof_path = MagicMock(return_value=[b"\x00" * 32] * 256)

        signing_key = nacl.signing.SigningKey(hash_bytes(b"test-key"))

        key = global_key("test-shard", record_key("document", "doc1", 1))
        value_hash = hash_bytes(b"value")

        # Simulate olympus_core being absent by making the import raise
        import builtins

        real_import = builtins.__import__

        def _fake_import(name: str, *args, **kwargs):
            if name == "olympus_core":
                raise ImportError("No module named 'olympus_core'")
            return real_import(name, *args, **kwargs)

        with patch("builtins.__import__", side_effect=_fake_import):
            with self.assertRaises(RuntimeError) as ctx:
                sl._append_record_inner(
                    shard_id="test-shard",
                    record_type="document",
                    record_id="doc1",
                    version=1,
                    key=key,
                    value_hash=value_hash,
                    signing_key=signing_key,
                    canonicalization=None,
                    poseidon_root=None,
                )

        self.assertIn("olympus_core is required", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
