"""
Tests for CDHSSMF (Constant-Depth Hierarchical Sparse Sharded Merkle Forest) implementation.

This module tests the global_key() function and the CDHSSMF design that collapses
the dual-tree structure (per-shard SMTs + forest SMT) into a single global SMT
with hierarchical key derivation.
"""

import pathlib

from protocol.hashes import global_key, record_key


class TestGlobalKey:
    """Test the global_key() function for CDHSSMF hierarchical key derivation."""

    def test_global_key_deterministic(self):
        """global_key() should produce identical output for identical inputs."""
        shard_id = "watauga:2025:budget"
        rec_key = record_key("document", "doc123", 1)

        key1 = global_key(shard_id, rec_key)
        key2 = global_key(shard_id, rec_key)

        assert key1 == key2
        assert len(key1) == 32

    def test_global_key_different_shards(self):
        """global_key() should produce different keys for different shards."""
        rec_key = record_key("document", "doc123", 1)

        key1 = global_key("shard_a", rec_key)
        key2 = global_key("shard_b", rec_key)

        assert key1 != key2
        assert len(key1) == 32
        assert len(key2) == 32

    def test_global_key_different_records(self):
        """global_key() should produce different keys for different records."""
        shard_id = "watauga:2025:budget"
        rec_key1 = record_key("document", "doc123", 1)
        rec_key2 = record_key("document", "doc456", 1)

        key1 = global_key(shard_id, rec_key1)
        key2 = global_key(shard_id, rec_key2)

        assert key1 != key2

    def test_global_key_accepts_variable_length_record_key_bytes(self):
        """global_key() should safely handle arbitrary byte lengths."""
        shard_id = "watauga:2025:budget"

        assert len(global_key(shard_id, b"short")) == 32
        assert len(global_key(shard_id, b"a" * 32)) == 32
        assert len(global_key(shard_id, b"a" * 33)) == 32

    def test_global_key_returns_32_bytes(self):
        """global_key() should always return exactly 32 bytes."""
        test_cases = [
            ("short", record_key("doc", "1", 1)),
            ("very-long-shard-identifier-name", record_key("doc", "2", 1)),
            ("watauga:2025:budget", record_key("policy", "abc", 999)),
        ]

        for shard_id, rec_key in test_cases:
            key = global_key(shard_id, rec_key)
            assert len(key) == 32, f"Failed for shard_id={shard_id}"

    def test_global_key_shard_isolation(self):
        """Keys from different shards should be cryptographically isolated."""
        # Create the same record in two different shards
        rec_key = record_key("document", "shared_doc_id", 1)

        key_shard1 = global_key("shard1", rec_key)
        key_shard2 = global_key("shard2", rec_key)

        # Keys should be completely different (no common prefix pattern)
        assert key_shard1 != key_shard2

        # Hamming distance should be high (cryptographic avalanche)
        diff_bits = sum(
            bin(a ^ b).count("1") for a, b in zip(key_shard1, key_shard2)
        )
        # Expect approximately 50% of bits to differ for good hash function
        assert diff_bits > 100, f"Only {diff_bits}/256 bits differ"

    def test_global_key_collision_resistance(self):
        """global_key() should avoid obvious collision patterns."""
        # Test that order of concatenation matters
        shard_a = "shard_a"
        shard_b = "shard_b"

        rec1 = record_key("doc", "1", 1)
        rec2 = record_key("doc", "2", 1)

        # These should all be unique
        keys = [
            global_key(shard_a, rec1),
            global_key(shard_a, rec2),
            global_key(shard_b, rec1),
            global_key(shard_b, rec2),
        ]

        # All keys should be unique
        assert len(set(keys)) == 4

    def test_global_key_unicode_shards(self):
        """global_key() should handle Unicode shard identifiers correctly."""
        rec_key = record_key("document", "doc123", 1)

        # Test various Unicode shard names
        unicode_shards = [
            "münchen:2025:budget",
            "東京:2025:記録",
            "москва:2025:档案",
        ]

        keys = [global_key(shard, rec_key) for shard in unicode_shards]

        # All should be valid 32-byte keys
        assert all(len(k) == 32 for k in keys)

        # All should be unique
        assert len(set(keys)) == len(unicode_shards)


class TestCDHSSMFSemantics:
    """Test CDHSSMF design semantics and correctness properties."""

    def test_hierarchical_namespace_encoding(self):
        """CDHSSMF should encode shards as namespaces in key space."""
        # The key insight: (shard_id, record_key) -> global_key is injective
        # This means no collisions across different (shard, record) pairs

        test_records = [
            ("shard1", "doc", "a", 1),
            ("shard1", "doc", "b", 1),
            ("shard2", "doc", "a", 1),
            ("shard2", "doc", "b", 1),
            ("shard1", "policy", "x", 1),
        ]

        global_keys = []
        for shard_id, rec_type, rec_id, version in test_records:
            rec_key = record_key(rec_type, rec_id, version)
            g_key = global_key(shard_id, rec_key)
            global_keys.append(g_key)

        # All global keys should be unique (injective mapping)
        assert len(set(global_keys)) == len(test_records)

    def test_single_tree_replaces_dual_tree(self):
        """CDHSSMF should eliminate need for separate forest tree."""
        # Before: needed a second cross-shard commitment layer.
        # After: single global SMT root commits to all shards

        # This is a semantic/architectural test - we verify that global_key()
        # provides sufficient isolation without needing a second tree layer

        # Create keys for multiple shards
        shards = ["shard_a", "shard_b", "shard_c"]
        records_per_shard = 3

        all_global_keys = set()
        for shard in shards:
            for i in range(records_per_shard):
                rec_key = record_key("doc", f"record_{i}", 1)
                g_key = global_key(shard, rec_key)
                all_global_keys.add(g_key)

        # All keys should be in a single namespace (no cross-shard collisions)
        expected_count = len(shards) * records_per_shard
        assert len(all_global_keys) == expected_count

        # This demonstrates that a single SMT with these keys can replace
        # the dual-tree structure (per-shard trees + forest tree)


def test_global_key_no_separator_collision():
    """
    (shard_id="ab", record_key=b"c") must not equal (shard_id="a", record_key=b"bc").
    This is the canonical separator-collision check.
    """
    k1 = global_key("ab", b"c")
    k2 = global_key("a", b"bc")
    assert k1 != k2, "separator collision: shard boundary shift produces same key"


def test_global_key_empty_shard():
    """Empty shard_id is valid and must not collide with non-empty shard_id."""
    k1 = global_key("", b"abc")
    k2 = global_key("a", b"bc")
    k3 = global_key("ab", b"c")
    assert len({k1, k2, k3}) == 3


def test_global_key_determinism():
    """Same inputs must always produce the same key."""
    record = b"record-abc"
    assert global_key("shard-1", record) == global_key("shard-1", record)


def test_global_key_is_32_bytes():
    assert len(global_key("any-shard", b"any-record")) == 32


def test_global_key_shard_isolation():
    """
    Two records with the same record_key in different shards must produce different
    global keys — this is the core CDHSSMF isolation guarantee.
    """
    record = b"identical-record-key"
    keys = [global_key(f"shard-{i}", record) for i in range(10)]
    assert len(set(keys)) == 10, "shard isolation broken: duplicate global keys across shards"


def test_global_key_context_uniqueness():
    """
    The derive_key context string must not be reused for any other hash in the codebase.
    This is a static check — read hashes.py and assert the context string appears once.
    """
    src = pathlib.Path("protocol/hashes.py").read_text()
    context = "olympus " + "2025-12 global-smt-leaf-key"
    assert src.count(context) == 1, "derive_key context string appears more than once"
