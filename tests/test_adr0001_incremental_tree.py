"""
Tests for ADR-0001: Incremental / paginated tree reconstruction.

Verifies the new StorageLayer helpers added by ADR-0001:
  - _get_proof_path()   — O(256) proof from smt_nodes
  - get_current_root()  — O(1) root from shard_headers
  - replay_tree_incremental() — O(N) streaming delta replay

Uses mocked psycopg cursors to avoid requiring a real Postgres instance.
"""

import unittest
from unittest.mock import MagicMock, patch

from protocol.hashes import global_key, record_key
from protocol.ssmf import (
    EMPTY_HASHES,
    ExistenceProof,
    NonExistenceProof,
    SparseMerkleTree,
    _key_to_path_bits,
)
from storage.postgres import StorageLayer


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_storage() -> StorageLayer:
    """Create a StorageLayer instance without connecting to a real database."""
    with patch.object(StorageLayer, "__init__", lambda self, *a, **kw: None):
        sl = object.__new__(StorageLayer)
        # Initialise attributes that the methods under test reference.
        sl._node_cache = {}
        sl._node_cache_maxsize = 4096
        sl._node_cache_lock = MagicMock()
        return sl


def _normalize_sql(statement: object) -> str:
    if isinstance(statement, str):
        text = statement
    else:
        text = str(statement)
    return " ".join(text.split())


def _build_tree_with_one_leaf() -> tuple[SparseMerkleTree, bytes, bytes]:
    """Insert a single leaf into a fresh SMT and return (tree, key, value_hash)."""
    tree = SparseMerkleTree()
    rec_key = record_key("document", "doc-1", 1)
    key = global_key("shard-1", rec_key)
    value_hash = b"\xab" * 32
    tree.update(key, value_hash)
    return tree, key, value_hash


# ---------------------------------------------------------------------------
# _get_proof_path
# ---------------------------------------------------------------------------


class TestGetProofPath(unittest.TestCase):
    """Tests for StorageLayer._get_proof_path."""

    def test_returns_256_siblings(self):
        """Proof path must contain exactly 256 sibling hashes."""
        sl = _make_storage()
        tree, key, _vh = _build_tree_with_one_leaf()

        # Simulate a cursor that returns in-memory node hashes when asked.
        path = tuple(_key_to_path_bits(key))
        node_lookup: dict[tuple[int, bytes], bytes] = {}
        for p, h in tree.nodes.items():
            node_lookup[(len(p), StorageLayer._encode_path(p))] = h

        def fake_execute(sql, params=None):
            pass  # no-op

        rows_to_return: list[tuple[bytes | None]] = []

        def build_rows():
            nonlocal rows_to_return
            rows_to_return = []
            for level in range(256):
                bit_pos = 255 - level
                sub_path = path[: bit_pos + 1]
                sibling_path = sub_path[:-1] + (1 - sub_path[-1],)
                db_level = len(sibling_path)
                db_index = StorageLayer._encode_path(sibling_path)
                h = node_lookup.get((db_level, db_index))
                rows_to_return.append((h,))

        build_rows()

        cur = MagicMock()
        cur.execute = MagicMock(side_effect=fake_execute)
        cur.fetchall = MagicMock(return_value=rows_to_return)

        siblings = sl._get_proof_path(cur, key)

        self.assertEqual(len(siblings), 256)
        # Verify each sibling is 32 bytes
        for s in siblings:
            self.assertEqual(len(s), 32)

    def test_missing_nodes_filled_with_empty_hashes(self):
        """Siblings absent from smt_nodes should be EMPTY_HASHES[level]."""
        sl = _make_storage()
        key = b"\x00" * 32

        # Return all NULLs (empty tree)
        cur = MagicMock()
        cur.fetchall.return_value = [(None,)] * 256

        siblings = sl._get_proof_path(cur, key)

        self.assertEqual(len(siblings), 256)
        for level, s in enumerate(siblings):
            self.assertEqual(s, EMPTY_HASHES[level])

    def test_proof_matches_in_memory_tree(self):
        """Proof from _get_proof_path must match SparseMerkleTree._collect_siblings."""
        sl = _make_storage()
        tree, key, _vh = _build_tree_with_one_leaf()

        path = tuple(_key_to_path_bits(key))
        expected_siblings = tree._collect_siblings(path)

        # Build the node lookup from tree.nodes
        node_lookup: dict[tuple[int, bytes], bytes] = {}
        for p, h in tree.nodes.items():
            node_lookup[(len(p), StorageLayer._encode_path(p))] = h

        rows_to_return: list[tuple[bytes | None]] = []
        for level in range(256):
            bit_pos = 255 - level
            sub_path = path[: bit_pos + 1]
            sibling_path = sub_path[:-1] + (1 - sub_path[-1],)
            db_level = len(sibling_path)
            db_index = StorageLayer._encode_path(sibling_path)
            h = node_lookup.get((db_level, db_index))
            rows_to_return.append((h,))

        cur = MagicMock()
        cur.fetchall.return_value = rows_to_return

        siblings = sl._get_proof_path(cur, key)

        self.assertEqual(siblings, expected_siblings)


# ---------------------------------------------------------------------------
# get_current_root
# ---------------------------------------------------------------------------


class TestGetCurrentRoot(unittest.TestCase):
    """Tests for StorageLayer.get_current_root."""

    def test_returns_root_from_shard_headers(self):
        """Should return the root from the latest shard header."""
        sl = _make_storage()
        expected_root = b"\x42" * 32

        mock_conn = MagicMock()
        mock_cur = MagicMock()
        mock_cur.fetchone.return_value = {"root": expected_root}
        mock_conn.cursor.return_value.__enter__ = MagicMock(return_value=mock_cur)
        mock_conn.cursor.return_value.__exit__ = MagicMock(return_value=False)
        mock_conn.__enter__ = MagicMock(return_value=mock_conn)
        mock_conn.__exit__ = MagicMock(return_value=False)

        sl._get_connection = MagicMock(return_value=mock_conn)

        root = sl.get_current_root("shard-1")

        self.assertEqual(root, expected_root)
        # Verify the correct SQL was used
        mock_cur.execute.assert_called_once()
        sql = mock_cur.execute.call_args[0][0]
        self.assertIn("shard_headers", sql)
        self.assertIn("ORDER BY seq DESC", sql)

    def test_returns_empty_tree_root_when_no_headers(self):
        """Should return EMPTY_HASHES[256] when no shard headers exist."""
        sl = _make_storage()

        mock_conn = MagicMock()
        mock_cur = MagicMock()
        mock_cur.fetchone.return_value = None
        mock_conn.cursor.return_value.__enter__ = MagicMock(return_value=mock_cur)
        mock_conn.cursor.return_value.__exit__ = MagicMock(return_value=False)
        mock_conn.__enter__ = MagicMock(return_value=mock_conn)
        mock_conn.__exit__ = MagicMock(return_value=False)

        sl._get_connection = MagicMock(return_value=mock_conn)

        root = sl.get_current_root("missing-shard")

        self.assertEqual(root, EMPTY_HASHES[256])


# ---------------------------------------------------------------------------
# get_proof / get_nonexistence_proof wiring
# ---------------------------------------------------------------------------


class TestProofEndpointsUseNodePath(unittest.TestCase):
    """Verify that get_proof and get_nonexistence_proof use _get_proof_path."""

    def test_get_proof_uses_proof_path(self):
        """get_proof should call _get_proof_path instead of _load_tree_state."""
        sl = _make_storage()
        tree, key, vh = _build_tree_with_one_leaf()
        expected_root = tree.get_root()
        expected_siblings = tree._collect_siblings(tree._key_to_path(key))

        mock_conn = MagicMock()
        mock_cur = MagicMock()
        # smt_leaves SELECT value_hash
        mock_cur.fetchone.return_value = {"value_hash": vh}
        mock_conn.cursor.return_value.__enter__ = MagicMock(return_value=mock_cur)
        mock_conn.cursor.return_value.__exit__ = MagicMock(return_value=False)
        mock_conn.__enter__ = MagicMock(return_value=mock_conn)
        mock_conn.__exit__ = MagicMock(return_value=False)

        sl._get_connection = MagicMock(return_value=mock_conn)
        sl._get_proof_path = MagicMock(return_value=expected_siblings)
        sl.get_current_root = MagicMock(return_value=expected_root)

        proof = sl.get_proof("shard-1", "document", "doc-1", 1)

        self.assertIsInstance(proof, ExistenceProof)
        self.assertEqual(proof.value_hash, vh)
        self.assertEqual(proof.root_hash, expected_root)
        self.assertEqual(proof.siblings, expected_siblings)
        sl._get_proof_path.assert_called_once()
        sl.get_current_root.assert_called_once_with("shard-1")

    def test_get_proof_returns_none_for_missing_leaf(self):
        """get_proof should return None when the leaf doesn't exist."""
        sl = _make_storage()

        mock_conn = MagicMock()
        mock_cur = MagicMock()
        mock_cur.fetchone.return_value = None  # leaf doesn't exist
        mock_conn.cursor.return_value.__enter__ = MagicMock(return_value=mock_cur)
        mock_conn.cursor.return_value.__exit__ = MagicMock(return_value=False)
        mock_conn.__enter__ = MagicMock(return_value=mock_conn)
        mock_conn.__exit__ = MagicMock(return_value=False)

        sl._get_connection = MagicMock(return_value=mock_conn)

        result = sl.get_proof("shard-1", "document", "missing", 1)

        self.assertIsNone(result)

    def test_get_nonexistence_proof_uses_proof_path(self):
        """get_nonexistence_proof should call _get_proof_path."""
        sl = _make_storage()
        expected_root = b"\x99" * 32
        expected_siblings = [EMPTY_HASHES[i] for i in range(256)]

        mock_conn = MagicMock()
        mock_cur = MagicMock()
        mock_cur.fetchone.return_value = None  # leaf doesn't exist
        mock_conn.cursor.return_value.__enter__ = MagicMock(return_value=mock_cur)
        mock_conn.cursor.return_value.__exit__ = MagicMock(return_value=False)
        mock_conn.__enter__ = MagicMock(return_value=mock_conn)
        mock_conn.__exit__ = MagicMock(return_value=False)

        sl._get_connection = MagicMock(return_value=mock_conn)
        sl._get_proof_path = MagicMock(return_value=expected_siblings)
        sl.get_current_root = MagicMock(return_value=expected_root)

        proof = sl.get_nonexistence_proof("shard-1", "document", "missing", 1)

        self.assertIsInstance(proof, NonExistenceProof)
        self.assertEqual(proof.root_hash, expected_root)
        self.assertEqual(proof.siblings, expected_siblings)
        sl._get_proof_path.assert_called_once()
        sl.get_current_root.assert_called_once_with("shard-1")


# ---------------------------------------------------------------------------
# verify_state_replay delegation
# ---------------------------------------------------------------------------


class TestVerifyStateReplayDelegation(unittest.TestCase):
    """verify_state_replay should delegate to replay_tree_incremental."""

    def test_delegates_to_replay_tree_incremental(self):
        sl = _make_storage()
        replay_result = {"verified": True, "headers_checked": 3, "next_seq": None}
        sl.replay_tree_incremental = MagicMock(return_value=replay_result)

        result = sl.verify_state_replay("shard-1")

        self.assertEqual(result, replay_result)
        sl.replay_tree_incremental.assert_called_once_with(
            "shard-1", max_headers=None, after_seq=0
        )


# ---------------------------------------------------------------------------
# _persist_tree_nodes uses DO UPDATE
# ---------------------------------------------------------------------------


class TestPersistTreeNodesDoUpdate(unittest.TestCase):
    """_persist_tree_nodes must use ON CONFLICT DO UPDATE (not DO NOTHING)."""

    def test_persist_uses_do_update(self):
        """SQL must contain DO UPDATE SET hash to keep smt_nodes current."""
        sl = _make_storage()
        sl.DEFAULT_FLUSH_BATCH_SIZE = 10_000

        tree = SparseMerkleTree()
        tree.update(b"\x00" * 32, b"\x01" * 32)

        cur = MagicMock()
        sl._cache_put = MagicMock()

        sl._persist_tree_nodes(cur, "shard-1", tree)

        # The first execute call should gate the trigger with the BLAKE3 hash.
        first_call_sql = _normalize_sql(cur.execute.call_args_list[0][0][0])
        self.assertIn("olympus.allow_node_rehash", first_call_sql)
        # Must NOT be a simple 'on' — must be the BLAKE3 gate.
        self.assertNotIn("= 'on'", first_call_sql)

        # executemany should have been called with SQL containing DO UPDATE
        call_args = cur.executemany.call_args
        sql = _normalize_sql(call_args[0][0])
        self.assertIn("DO UPDATE SET hash = EXCLUDED.hash", sql)
        self.assertNotIn("DO NOTHING", sql)


# ---------------------------------------------------------------------------
# protocol_state.persist_tree_nodes uses DO UPDATE
# ---------------------------------------------------------------------------


class TestProtocolStatePersistDoUpdate(unittest.TestCase):
    """persist_tree_nodes in protocol_state.py must use DO UPDATE."""

    def test_persist_uses_do_update(self):
        from storage.protocol_state import persist_tree_nodes

        tree = SparseMerkleTree()
        tree.update(b"\x00" * 32, b"\x01" * 32)

        cur = MagicMock()
        persist_tree_nodes(cur, None, tree)

        # First call must gate the trigger with the BLAKE3 hash.
        first_call_sql = _normalize_sql(cur.execute.call_args_list[0][0][0])
        self.assertIn("olympus.allow_node_rehash", first_call_sql)
        self.assertNotIn("= 'on'", first_call_sql)

        # Each INSERT call should contain DO UPDATE
        for call in cur.execute.call_args_list:
            sql = _normalize_sql(call[0][0])
            if "smt_nodes" in sql:
                self.assertIn("DO UPDATE SET hash = EXCLUDED.hash", sql)
                self.assertNotIn("DO NOTHING", sql)


if __name__ == "__main__":
    unittest.main()
