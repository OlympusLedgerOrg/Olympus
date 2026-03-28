"""
Tests for CDHSSMF (Constant-Depth Hierarchical Sparse Sharded Merkle Forest) implementation.

This module tests the global_key() function and the CDHSSMF design that collapses
the dual-tree structure (per-shard SMTs + forest SMT) into a single global SMT
with hierarchical key derivation.
"""

import pytest

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

    def test_global_key_length_validation(self):
        """global_key() should reject invalid record_key lengths."""
        shard_id = "watauga:2025:budget"

        # Valid 32-byte key should work
        valid_key = b"a" * 32
        global_key(shard_id, valid_key)  # Should not raise

        # Invalid lengths should raise ValueError
        with pytest.raises(ValueError, match="record_key must be 32 bytes"):
            global_key(shard_id, b"short")

        with pytest.raises(ValueError, match="record_key must be 32 bytes"):
            global_key(shard_id, b"a" * 33)

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
        # Before: needed forest_root(shard_roots) for cross-shard commitment
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
