"""Stateful property-based tests for SparseMerkleTree.

Uses ``hypothesis.stateful.RuleBasedStateMachine`` to explore interleaved
sequences of insert/update, existence-prove, and non-existence-prove
operations and assert that cryptographic invariants hold at every step.
"""

from __future__ import annotations

import os

import hypothesis.strategies as st
from hypothesis import settings
from hypothesis.stateful import RuleBasedStateMachine, initialize, rule

from protocol.ssmf import (
    SparseMerkleTree,
    verify_unified_proof,
)


# 32-byte keys and values — matching the protocol's fixed-size constraint.
_keys = st.binary(min_size=32, max_size=32)
_values = st.binary(min_size=32, max_size=32)

_DEADLINE_MS = int(os.environ.get("HYPOTHESIS_DEADLINE_MS", "2000"))


class SMTStateMachine(RuleBasedStateMachine):
    """State machine for SparseMerkleTree.

    Maintains a shadow dictionary of key → value_hash pairs that mirrors the
    expected state of the tree.  Each rule mutates both the real tree and the
    shadow simultaneously, then asserts that the cryptographic invariants
    still hold.
    """

    @initialize()
    def setup(self) -> None:
        """Create a fresh tree and an empty shadow dictionary."""
        self.tree: SparseMerkleTree = SparseMerkleTree()
        self.shadow: dict[bytes, bytes] = {}

    # ── Rule 1: insert / update ───────────────────────────────────────────

    @rule(key=_keys, value=_values)
    def insert_or_update(self, key: bytes, value: bytes) -> None:
        """Insert or overwrite a key-value pair and mirror it in the shadow."""
        self.tree.update(key, value)
        self.shadow[key] = value

    # ── Rule 2: prove existence of an inserted key ────────────────────────

    @rule(key=_keys)
    def prove_existence(self, key: bytes) -> None:
        """Prove existence of a key that is known to be in the tree.

        Skips silently when the key has not been inserted yet so that this
        rule does not bias the distribution of test cases.
        """
        if key not in self.shadow:
            return

        proof = self.tree.prove_existence(key)
        assert verify_unified_proof(proof), (
            f"verify_unified_proof failed for existing key {key.hex()}"
        )
        assert proof.key == key, "Proof key mismatch"
        assert proof.value_hash == self.shadow[key], (
            f"Proof value_hash mismatch for key {key.hex()}: "
            f"expected {self.shadow[key].hex()}, got {proof.value_hash.hex()}"
        )
        assert proof.root_hash == self.tree.get_root(), (
            "Proof root_hash does not match current tree root"
        )

    # ── Rule 3: prove non-existence of an absent key ──────────────────────

    @rule(key=_keys)
    def prove_nonexistence(self, key: bytes) -> None:
        """Prove non-existence of a key that has never been inserted.

        Skips silently when the key is already in the shadow dictionary.
        """
        if key in self.shadow:
            return

        proof = self.tree.prove_nonexistence(key)
        assert verify_unified_proof(proof), (
            f"verify_unified_proof failed for absent key {key.hex()}"
        )
        assert proof.key == key, "Non-existence proof key mismatch"
        assert proof.root_hash == self.tree.get_root(), (
            "Non-existence proof root_hash does not match current tree root"
        )


# Expose as a standard ``unittest.TestCase`` so pytest and unittest discover it.
TestSMTStateMachine = SMTStateMachine.TestCase
TestSMTStateMachine.settings = settings(
    max_examples=200,
    deadline=_DEADLINE_MS,
    stateful_step_count=30,
)
