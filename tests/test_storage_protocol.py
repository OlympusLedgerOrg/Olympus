"""
Tests for storage/protocol_state.py module.

Uses mocked psycopg cursor/connection to avoid requiring a real Postgres instance.
"""

import unittest
from datetime import datetime, timezone
from unittest.mock import MagicMock

from storage.protocol_state import (
    _row_get,
    assert_root_matches_state,
    encode_path,
    get_header_by_seq,
    load_tree_state,
    persist_tree_nodes,
)


def _normalize_sql(statement: object) -> str:
    if isinstance(statement, str):
        text = statement
    elif hasattr(statement, "as_string"):
        text = statement.as_string(None)
    else:
        text = str(statement)
    return " ".join(text.split())


class TestLoadTreeState(unittest.TestCase):
    """Tests for load_tree_state function."""

    def test_load_tree_state_empty(self):
        """Returns empty tree when no rows exist in database."""
        cur = MagicMock()
        cur.fetchmany.return_value = []

        tree = load_tree_state(cur)

        cur.execute.assert_called_once()
        # Empty tree should have the precomputed empty root (level 256)
        from protocol.ssmf import EMPTY_HASHES

        self.assertEqual(tree.get_root(), EMPTY_HASHES[256])

    def test_load_tree_state_with_rows(self):
        """Returns correct tree state when rows exist."""
        cur = MagicMock()
        # Simulate rows as tuples (key, value_hash)
        key1 = b"\x00" * 32
        value1 = b"\x01" * 32
        key2 = b"\x02" * 32
        value2 = b"\x03" * 32
        cur.fetchmany.side_effect = [
            [(key1, value1), (key2, value2)],
            [],
        ]

        tree = load_tree_state(cur)

        # Verify tree has the leaves
        self.assertEqual(tree.leaves.get(key1), value1)
        self.assertEqual(tree.leaves.get(key2), value2)

    def test_load_tree_state_with_timestamp_cutoff_string(self):
        """Handles timestamp cutoff as ISO string."""
        cur = MagicMock()
        cur.fetchmany.return_value = []

        _tree = load_tree_state(cur, up_to_ts="2024-01-01T00:00:00Z")  # noqa: F841

        # Should have called execute with timestamp parameter
        args, kwargs = cur.execute.call_args
        self.assertIn("%s", args[0])  # SQL has parameter placeholder
        self.assertEqual(len(args[1]), 1)  # One parameter (the cutoff)

    def test_load_tree_state_with_timestamp_cutoff_datetime(self):
        """Handles timestamp cutoff as datetime object."""
        cur = MagicMock()
        cur.fetchmany.return_value = []
        cutoff = datetime(2024, 1, 1, tzinfo=timezone.utc)

        _tree = load_tree_state(cur, up_to_ts=cutoff)  # noqa: F841

        args, kwargs = cur.execute.call_args
        self.assertIn("WHERE ts <=", args[0])

    def test_load_tree_state_with_dict_rows(self):
        """Handles rows returned as dictionaries."""
        cur = MagicMock()
        key1 = b"\x00" * 32
        value1 = b"\x01" * 32
        cur.fetchmany.side_effect = [
            [{"key": key1, "value_hash": value1}],
            [],
        ]

        tree = load_tree_state(cur)

        self.assertEqual(tree.leaves.get(key1), value1)

    def test_load_tree_state_batched_iteration(self):
        """Rows are fetched in batches to bound peak memory (RT-M2)."""
        cur = MagicMock()
        key1 = b"\x00" * 32
        value1 = b"\x01" * 32
        key2 = b"\x02" * 32
        value2 = b"\x03" * 32
        # Simulate two batches of size 1, then empty
        cur.fetchmany.side_effect = [
            [(key1, value1)],
            [(key2, value2)],
            [],
        ]

        tree = load_tree_state(cur, batch_size=1)

        self.assertEqual(tree.leaves.get(key1), value1)
        self.assertEqual(tree.leaves.get(key2), value2)
        # fetchmany should have been called 3 times (2 batches + 1 empty)
        self.assertEqual(cur.fetchmany.call_count, 3)

    def test_load_tree_state_invalid_batch_size(self):
        """batch_size < 1 raises ValueError."""
        cur = MagicMock()
        with self.assertRaises(ValueError) as ctx:
            load_tree_state(cur, batch_size=0)
        self.assertIn("batch_size", str(ctx.exception))


class TestPersistTreeNodes(unittest.TestCase):
    """Tests for persist_tree_nodes function."""

    def test_persist_tree_nodes_success(self):
        """Successfully persists tree nodes to database."""
        cur = MagicMock()

        # Create a mock tree with some nodes
        tree = MagicMock()
        tree.nodes = {
            (0, 1): b"\xaa" * 32,
            (1, 0, 1): b"\xbb" * 32,
        }

        persist_tree_nodes(cur, "test-shard", tree)

        # 1 SET LOCAL gate + 2 INSERT calls = 3 total
        self.assertEqual(cur.execute.call_count, 3)

    def test_persist_tree_nodes_with_cache_put(self):
        """Calls cache_put callback when provided."""
        cur = MagicMock()
        cache_put = MagicMock()

        tree = MagicMock()
        path = (0, 1, 1)
        hash_value = b"\xcc" * 32
        tree.nodes = {path: hash_value}

        persist_tree_nodes(cur, "shard-1", tree, cache_put=cache_put)

        # Verify cache_put was called with correct arguments
        cache_put.assert_called_once()
        call_args = cache_put.call_args[0]
        self.assertEqual(call_args[0], "shard-1")  # shard_id
        self.assertEqual(call_args[1], 3)  # level = len(path)
        self.assertEqual(call_args[2], encode_path(path))  # path_bytes
        self.assertEqual(call_args[3], hash_value)  # hash_value

    def test_persist_tree_nodes_empty(self):
        """Handles empty tree nodes gracefully."""
        cur = MagicMock()
        tree = MagicMock()
        tree.nodes = {}

        persist_tree_nodes(cur, None, tree)

        # Only the SET LOCAL gate call should have been made; no INSERT.
        self.assertEqual(cur.execute.call_count, 1)
        gate_sql = _normalize_sql(cur.execute.call_args_list[0][0][0])
        self.assertIn("olympus.allow_node_rehash", gate_sql)


class TestEncodePath(unittest.TestCase):
    """Tests for encode_path function."""

    def test_encode_path_empty(self):
        """Empty path returns empty bytes."""
        result = encode_path(())
        self.assertEqual(result, b"")

    def test_encode_path_short(self):
        """Short path (< 8 bits) encodes correctly."""
        # (1, 0, 1) = 0b10100000 = 0xA0
        result = encode_path((1, 0, 1))
        self.assertEqual(result, b"\xa0")

    def test_encode_path_one_byte(self):
        """8-bit path encodes to 1 byte."""
        # (1,1,1,1,1,1,1,1) = 0xFF
        result = encode_path((1, 1, 1, 1, 1, 1, 1, 1))
        self.assertEqual(result, b"\xff")

    def test_encode_path_full_256_bit(self):
        """Full 256-bit path encodes to 32 bytes."""
        # All zeros
        path = tuple([0] * 256)
        result = encode_path(path)
        self.assertEqual(len(result), 32)
        self.assertEqual(result, b"\x00" * 32)

        # All ones
        path = tuple([1] * 256)
        result = encode_path(path)
        self.assertEqual(len(result), 32)
        self.assertEqual(result, b"\xff" * 32)

    def test_encode_path_mixed(self):
        """Mixed bit path encodes correctly."""
        # 16 bits: 0b1010101010101010 = 0xAAAA
        path = (1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0)
        result = encode_path(path)
        self.assertEqual(result, b"\xaa\xaa")


class TestGetHeaderBySeq(unittest.TestCase):
    """Tests for get_header_by_seq function."""

    def test_get_header_by_seq_found(self):
        """Returns header row when found."""
        cur = MagicMock()
        expected_row = {
            "seq": 5,
            "root": b"\x00" * 32,
            "header_hash": b"\x01" * 32,
            "previous_header_hash": b"\x02" * 32,
            "ts": datetime(2024, 1, 1, tzinfo=timezone.utc),
        }
        cur.fetchone.return_value = expected_row

        result = get_header_by_seq(cur, "test-shard", 5)

        self.assertEqual(result, expected_row)
        cur.execute.assert_called_once()
        # Verify SQL parameters
        args = cur.execute.call_args[0]
        self.assertEqual(args[1], ("test-shard", 5))

    def test_get_header_by_seq_not_found(self):
        """Returns None when header not found."""
        cur = MagicMock()
        cur.fetchone.return_value = None

        result = get_header_by_seq(cur, "nonexistent-shard", 999)

        self.assertIsNone(result)


class TestAssertRootMatchesState(unittest.TestCase):
    """Tests for assert_root_matches_state function."""

    def test_assert_root_matches_state_passes(self):
        """Passes when computed root matches expected root."""
        cur = MagicMock()
        cur.fetchmany.return_value = []  # Empty tree

        # Get the default root from an empty tree
        from protocol.ssmf import SparseMerkleTree

        empty_tree = SparseMerkleTree()
        expected_root = empty_tree.get_root()

        # Should not raise
        assert_root_matches_state(cur, None, expected_root)

    def test_assert_root_matches_state_raises_on_mismatch(self):
        """Raises ValueError when roots diverge."""
        cur = MagicMock()
        cur.fetchmany.return_value = []  # Empty tree

        # Provide a wrong expected root
        wrong_root = b"\xff" * 32

        with self.assertRaises(ValueError) as ctx:
            assert_root_matches_state(cur, None, wrong_root)

        self.assertIn("does not match", str(ctx.exception))

    def test_assert_root_matches_state_includes_shard_in_error(self):
        """Error message includes shard_id when provided."""
        cur = MagicMock()
        cur.fetchmany.return_value = []
        wrong_root = b"\xff" * 32

        with self.assertRaises(ValueError) as ctx:
            assert_root_matches_state(cur, "my-shard", wrong_root)

        self.assertIn("my-shard", str(ctx.exception))


class TestRowGet(unittest.TestCase):
    """Tests for _row_get helper function."""

    def test_row_get_with_dict(self):
        """Works with dict row using key access."""
        row = {"name": "Alice", "age": 30}

        self.assertEqual(_row_get(row, "name", 0), "Alice")
        self.assertEqual(_row_get(row, "age", 1), 30)

    def test_row_get_with_tuple(self):
        """Works with tuple row using index access."""
        row = ("Alice", 30)

        self.assertEqual(_row_get(row, "name", 0), "Alice")
        self.assertEqual(_row_get(row, "age", 1), 30)

    def test_row_get_with_list(self):
        """Works with list row using index access."""
        row = ["Alice", 30]

        self.assertEqual(_row_get(row, "name", 0), "Alice")
        self.assertEqual(_row_get(row, "age", 1), 30)


if __name__ == "__main__":
    unittest.main()
